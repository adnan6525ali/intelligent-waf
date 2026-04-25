from flask import Flask, request, jsonify, render_template, abort
from predict import predict
import json
from datetime import datetime

app = Flask(__name__)

# ── Request Log (in-memory) ───────────────────────────────────────
request_log = []


# ── Helper ───────────────────────────────────────────────────────
def log_request(method, url, content, result):
    request_log.append({
        'timestamp' : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'method'    : method,
        'url'       : url[:80] + '...' if len(url) > 80 else url,
        'label'     : result['label'],
        'confidence': result['confidence'],
        'blocked'   : result['is_attack']
    })
    # Keep only last 50 entries
    if len(request_log) > 50:
        request_log.pop(0)


# ── Routes ───────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Main WAF dashboard."""
    return render_template('dashboard.html', logs=request_log)


@app.route('/inspect', methods=['POST'])
def inspect():
    """
    Main WAF inspection endpoint.
    Accepts JSON: { "url": "...", "content": "...", "method": "GET" }
    Returns classification result.
    Blocks request if attack detected.
    """
    data    = request.get_json(force=True)
    url     = data.get('url', '/')
    content = data.get('content', '')
    method  = data.get('method', 'GET')

    result = predict(url, content, method)
    log_request(method, url, content, result)

    if result['is_attack']:
        return jsonify({
            'status'    : 'BLOCKED',
            'message'   : '🚫 Request blocked by WAF — Attack detected',
            'label'     : result['label'],
            'confidence': f"{result['confidence']}%",
            'detection' : result.get('detection', 'Bi-LSTM'),
            'probability': result['probability'],
            'features'  : result['features']
        }), 403
    else:
        return jsonify({
            'status'    : 'ALLOWED',
            'message'   : '✅ Request allowed — Normal traffic',
            'label'     : result['label'],
            'confidence': f"{result['confidence']}%",
            'detection' : result.get('detection', 'Bi-LSTM'),
            'probability': result['probability'],
            'features'  : result['features']
        }), 200


@app.route('/logs')
def logs():
    """Return request logs as JSON."""
    return jsonify(request_log)


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'WAF running ✅', 'model': 'Bi-LSTM'})


if __name__ == '__main__':
    print("=" * 50)
    print("  🔥 Intelligent WAF — Bi-LSTM Powered")
    print("  🌐 Dashboard: http://localhost:5000")
    print("  📡 Inspect:   http://localhost:5000/inspect")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5001)