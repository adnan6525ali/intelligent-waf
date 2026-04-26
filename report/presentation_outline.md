# Presentation Outline
## Intelligent WAF Using Deep Learning
### M.Tech Cybersecurity — Final Presentation

---

## Slide 1 — Title Slide
- Project title
- Your name, roll number
- Guide name
- Institution name, year

## Slide 2 — Problem Statement (1 min)
- Web attacks increasing year by year
- Signature-based WAFs fail against zero-day attacks
- ModSecurity misses novel attack patterns
- Need: Intelligent WAF that learns from data

## Slide 3 — Proposed Solution (1 min)
- Deep learning-based WAF
- Bi-LSTM + Attention mechanism
- Character-level HTTP traffic analysis
- Hybrid: Rules + Deep Learning

## Slide 4 — Dataset (1 min)
- CSIC 2010 HTTP Dataset
- 61,065 samples (36,000 normal + 25,065 attacks)
- Attack types: SQLi, XSS, Path Traversal, CSRF, etc.
- Show class distribution chart

## Slide 5 — System Architecture (2 min)
- Show full pipeline diagram:
  HTTP Request → Tokenization → Bi-LSTM → Classification → Block/Allow
- Explain each component

## Slide 6 — Model Comparison (2 min)
- Show comparison bar chart
- LSTM vs Bi-LSTM vs Transformer vs ModSecurity
- Highlight Bi-LSTM winning on all metrics

## Slide 7 — Key Results (2 min)
- Show results table
- Accuracy: 96.02%
- F1-Score: 94.92%
- ROC-AUC: 99.50%
- FPR: 0.30% (vs ModSecurity 10%)

## Slide 8 — ROC Curve (1 min)
- Show ROC curve comparison
- Bi-LSTM dominates across all thresholds

## Slide 9 — Firewall Demo (2 min)
- Live demo of Flask dashboard
- Show normal request being allowed
- Show SQL injection being blocked
- Show XSS being blocked

## Slide 10 — Conclusion (1 min)
- Bi-LSTM outperforms ModSecurity by 14.2%
- 97% reduction in false positive rate
- Working real-time prototype demonstrated
- Future work

## Slide 11 — References
- Key papers cited
