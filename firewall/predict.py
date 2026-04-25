import torch
import torch.nn as nn
import numpy as np
import re
import os

# ── Bi-LSTM Model Definition ─────────────────────────────────────
class BiLSTMClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim,
                 num_layers, num_numerical, dropout=0.4):
        super(BiLSTMClassifier, self).__init__()
        self.embedding     = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.embed_dropout = nn.Dropout(dropout)
        self.bilstm        = nn.LSTM(
            embed_dim, hidden_dim, num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        self.dropout    = nn.Dropout(dropout)
        lstm_out_dim    = hidden_dim * 2
        self.attention  = nn.Linear(lstm_out_dim, 1)
        self.fc = nn.Sequential(
            nn.Linear(lstm_out_dim + num_numerical, 128),
            nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(64, 1), nn.Sigmoid()
        )

    def attention_layer(self, lstm_output):
        attn_weights = torch.softmax(self.attention(lstm_output), dim=1)
        return (lstm_output * attn_weights).sum(dim=1)

    def forward(self, x_seq, x_num):
        x = self.embed_dropout(self.embedding(x_seq))
        lstm_out, _ = self.bilstm(x)
        attended = self.attention_layer(self.dropout(lstm_out))
        return self.fc(torch.cat([attended, x_num], dim=1)).squeeze(1)


# ── Constants ─────────────────────────────────────────────────────
MAX_LEN   = 200
VOCAB_SIZE = 50
DEVICE    = torch.device('cpu')  # CPU for local inference

# Character vocabulary (same as training)
VOCAB = {
    '<PAD>': 0, '<UNK>': 1,
    'a':2,'b':3,'c':4,'d':5,'e':6,'f':7,'g':8,'h':9,'i':10,
    'j':11,'k':12,'l':13,'m':14,'n':15,'o':16,'p':17,'q':18,
    'r':19,'s':20,'t':21,'u':22,'v':23,'w':24,'x':25,'y':26,
    'z':27,'0':28,'1':29,'2':30,'3':31,'4':32,'5':33,'6':34,
    '7':35,'8':36,'9':37,' ':38,'/':39,'?':40,'=':41,'&':42,
    '%':43,'+':44,'-':45,'_':46,'.':47,'<':48,'>':49
}


# ── Load Model ────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__),
                          '..', 'models', 'bilstm_model.pth')

model = BiLSTMClassifier(
    vocab_size=VOCAB_SIZE, embed_dim=64, hidden_dim=128,
    num_layers=2, num_numerical=8, dropout=0.4
)
model.load_state_dict(
    torch.load(MODEL_PATH, map_location=DEVICE)
)
model.eval()
print("✅ Bi-LSTM model loaded successfully")


# ── Feature Extraction ────────────────────────────────────────────
def extract_features(url: str, content: str, method: str) -> dict:
    """Extract numerical features from HTTP request."""
    text = (url or '') + ' ' + (content or '')

    has_sql = int(bool(re.search(
        r"\b(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|passwd|username|password)\b|--|;|\bOR\s+1\s*=\s*1\b|\b1\s*=\s*1\b",
        text, re.IGNORECASE)))
    has_xss = int(bool(re.search(
        r"script|alert|document\.cookie|onerror|onload|javascript|eval|iframe",
        text, re.IGNORECASE)))
    has_path = int(bool(re.search(
        r"\.\./|\.\.\\|%2e|\.\.\.\./|etc/passwd|/etc/|/windows/",
        text, re.IGNORECASE)))

    method_map = {'GET': 0, 'POST': 1, 'PUT': 2,
                  'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}
    method_enc = method_map.get(method.upper(), 0)

    special_chars = sum(text.count(c)
                        for c in ['"',"'",'<','>',';','=','&','%','+'])

    return {
        'url_length'       : len(url or ''),
        'content_length'   : len(content or ''),
        'has_sql'          : has_sql,
        'has_xss'          : has_xss,
        'has_path_traversal': has_path,
        'method_encoded'   : method_enc,
        'special_char_count': special_chars,
        'length'           : len(content or '')
    }


def tokenize_text(url: str, content: str) -> list:
    """Convert URL+content to character index sequence."""
    text = ((url or '') + ' ' + (content or '')).lower()
    tokens = [VOCAB.get(c, 1) for c in text]  # 1 = <UNK>

    # Pad or truncate to MAX_LEN
    if len(tokens) < MAX_LEN:
        tokens += [0] * (MAX_LEN - len(tokens))
    else:
        tokens = tokens[:MAX_LEN]
    return tokens


# ── Main Prediction Function ──────────────────────────────────────
# ── Rule-based attack signatures (override layer) ─────────────────
ATTACK_SIGNATURES = [
    # SQL Injection
    r"union\s+select", r"select\s+.+\s+from", r"insert\s+into",
    r"drop\s+table", r"delete\s+from", r"update\s+.+\s+set",
    r"or\s+1\s*=\s*1", r"or\s+'1'\s*=\s*'1", r"admin'\s*--",
    r"'\s*or\s*'", r"1=1", r"--\s*$", r";\s*drop", r";\s*select",
    # XSS
    r"<script", r"</script", r"javascript:", r"onerror\s*=",
    r"onload\s*=", r"alert\s*\(", r"document\.cookie",
    r"eval\s*\(", r"iframe", r"<img\s+src",
    # Path Traversal
    r"\.\./", r"\.\.\\", r"etc/passwd", r"etc/shadow",
    r"/windows/system32", r"%2e%2e", r"\.\.%2f",
    # Command Injection
    r";\s*ls", r";\s*cat", r";\s*wget", r"\|\s*bash",
    r"`.*`", r"\$\(.*\)",
]

def rule_based_check(url: str, content: str) -> tuple:
    """Check request against known attack signatures."""
    text = ((url or '') + ' ' + (content or '')).lower()
    for pattern in ATTACK_SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE):
            return True, pattern
    return False, None


def predict(url: str, content: str = '',
            method: str = 'GET') -> dict:
    """
    Classify HTTP request using Rule-based check + Bi-LSTM model.
    Rule-based check runs first — if attack signature found → BLOCK immediately.
    If no signature found → use Bi-LSTM model for final decision.
    """
    # ── Layer 1: Rule-based check ──
    is_rule_attack, matched_rule = rule_based_check(url, content)

    if is_rule_attack:
        return {
            'label'      : 'ATTACK',
            'confidence' : 99.9,
            'is_attack'  : True,
            'probability': 0.999,
            'features'   : extract_features(url, content, method),
            'detection'  : f'Rule-based: {matched_rule}'
        }

    # ── Layer 2: Bi-LSTM model ──
    seq   = tokenize_text(url, content)
    x_seq = torch.tensor([seq], dtype=torch.long)

    feats = extract_features(url, content, method)
    x_num = torch.tensor(
        [[feats['url_length'], feats['content_length'],
          feats['has_sql'], feats['has_xss'],
          feats['has_path_traversal'], feats['method_encoded'],
          feats['special_char_count'], feats['length']]],
        dtype=torch.float32
    )

    with torch.no_grad():
        prob = model(x_seq, x_num).item()

    is_attack  = prob >= 0.5
    label      = 'ATTACK' if is_attack else 'NORMAL'
    confidence = prob if is_attack else (1 - prob)

    return {
        'label'      : label,
        'confidence' : round(confidence * 100, 2),
        'is_attack'  : is_attack,
        'probability': round(prob, 4),
        'features'   : feats,
        'detection'  : 'Bi-LSTM model'
    }