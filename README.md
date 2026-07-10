# CodeAegis: Vulnerability Classifier
### AI-Powered Security Log Analysis using BERT

[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-ee4c2c?logo=pytorch&logoColor=white)](https://pytorch.org)
[![Transformers](https://img.shields.io/badge/HuggingFace-Transformers-yellow?logo=huggingface&logoColor=white)](https://huggingface.co)
[![Flask](https://img.shields.io/badge/Flask-REST%20API-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Accuracy](https://img.shields.io/badge/Accuracy-92%25-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

---

## 📌 Overview

Security teams receive **thousands of error logs daily** from static analysis tools like Bandit, Flawfinder, and SonarQube — and manually triaging each one is impractical. This project automates that triage.

**Vulnerability Classifier** is a fine-tuned BERT model that reads security tool output logs and classifies them as either **Vulnerable** or **Safe**, with a calibrated confidence score. It goes beyond keyword matching by learning *semantic meaning* — understanding that `[PATCHED] strcpy issue resolved` is **Safe**, even though it mentions a classic vulnerability keyword.

The system is deployed as a **full-stack web application** (HTML + Flask REST API) and also supports an **interactive terminal mode** for quick testing — no browser required.

---

## ✨ Key Features

| Feature | Detail |
|---|---|
| 🧠 **BERT-based Classification** | Fine-tuned `bert-base-uncased` with multi-head attention |
| 📊 **92% Accuracy** | Validated on 4,000+ held-out test samples |
| 🎯 **Confidence Calibration** | Rule-adjusted scores reduce false positives intelligently |
| 🔧 **Multi-tool Support** | Handles Bandit, Flawfinder, SonarQube, and more |
| 🌐 **Web Interface** | Paste a log, get results instantly in the browser |
| 💻 **Terminal Mode** | Interactive CLI for testing without a browser |
| ⚡ **Fast Inference** | ~100–200ms per log on CPU; ~20ms on GPU |

---

## 🏗️ System Architecture

```
User Input (Log Text)
        │
        ▼
┌───────────────────┐
│   Frontend (HTML) │  ← Paste log, view result + confidence bar
└────────┬──────────┘
         │  HTTP POST /api/predict
         ▼
┌────────────────────┐
│  Flask Backend     │  ← Tokenizes input, runs inference, calibrates score
└────────┬───────────┘
         │
         ▼
┌────────────────────────────────────────────┐
│         BERT Deep Learning Model           │
│  ┌──────────────────────────────────────┐  │
│  │  bert-base-uncased (110M params)     │  │
│  │       ↓                              │  │
│  │  Multi-head Attention (8 heads)      │  │
│  │       ↓                              │  │
│  │  Dense Head: 768 → 512 → 128 → 2    │  │
│  │       ↓                              │  │
│  │  [P(Safe), P(Vulnerable)]            │  │
│  └──────────────────────────────────────┘  │
│         + Confidence Calibration Layer     │
└────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
vulnerability-classifier/
│
├── improved_vulnerability_classifier.py  # Model definition, data generation, training
├── flask_backend.py                      # REST API server
├── index.html                            # Frontend web UI
│
├── models/
│   └── best_model_minimal.pth            # Saved model weights (after training)
│
├── data/
│   ├── full_dataset_minimal.csv          # All 20,000+ generated samples
│   ├── train_dataset_minimal.csv         # 60% split
│   ├── val_dataset_minimal.csv           # 20% split
│   └── test_dataset_minimal.csv          # 20% split
│
└── results/
    ├── test_results_minimal.json         # Evaluation metrics
    └── classification_report_minimal.txt # Per-class precision/recall/F1
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- 4 GB RAM minimum (8 GB recommended)
- GPU optional but speeds up training ~5–10×

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/vulnerability-classifier.git
cd vulnerability-classifier

pip install torch transformers flask flask-cors pandas numpy scikit-learn tqdm matplotlib seaborn
```

### 2. Train the Model *(one-time, ~10–30 min)*

> **Skip this if a pre-trained `models/best_model_minimal.pth` is already present.**

```bash
python improved_vulnerability_classifier.py --train
```

Expected output:
```
✓ Generated 20,000+ synthetic samples
✓ Training complete — Epoch 20/20
──────────────────────────────────
Test Results:
  Accuracy:  0.9205
  Precision: 0.9045
  Recall:    0.9312
  F1 Score:  0.9177
  ROC AUC:   0.9723
✓ Model saved → models/best_model_minimal.pth
```

---

## 🌐 Option A: Web Interface

**Step 1** — Start the backend API:
```bash
python flask_backend.py
```

**Step 2** — Serve the frontend (in a new terminal):
```bash
python -m http.server 8000
```

**Step 3** — Open in browser:
```
http://localhost:8000
```

Paste any security log into the input box, click **Analyze**, and see the prediction with a live confidence bar.

---

## 💻 Option B: Interactive Terminal Mode

No browser needed. Run the classifier interactively in your terminal:

```bash
python improved_vulnerability_classifier.py --interactive
```

```
╔══════════════════════════════════════════════════╗
║       Vulnerability Classifier — Terminal Mode   ║
║       Type 'quit' to exit | 'examples' for demos ║
╚══════════════════════════════════════════════════╝

Enter log > ./main.c:45: strcpy: Does not check for buffer overflows (CWE-120)

──────────────────────────────────────────
  Result      : ⚠  VULNERABLE
  Confidence  : 92.3%  [HIGH]
  Safe prob   : 7.7%
  Vuln prob   : 92.3%
──────────────────────────────────────────

Enter log > [PATCHED] Replaced strcpy with strncpy_s (CWE-120 resolved)

──────────────────────────────────────────
  Result      : ✅ SAFE
  Confidence  : 87.1%  [HIGH]
  Safe prob   : 87.1%
  Vuln prob   : 12.9%
──────────────────────────────────────────
```

---

## 🧪 Example Test Cases

| Log | Expected | Reason |
|---|---|---|
| `./main.c:45: strcpy: Does not check for buffer overflows (CWE-120)` | ⚠️ Vulnerable ~92% | Flawfinder format, direct CWE mention |
| `[PATCHED] Replaced strcpy with strncpy_s (CWE-120 resolved)` | ✅ Safe ~87% | `[PATCHED]` + `resolved` → fixed issue |
| `[bandit] Use of 'pickle' is insecure, potential code execution (B403)` | ⚠️ Vulnerable ~89% | Bandit alert, explicit threat language |
| `Function analysis: string operation in authentication module` | ✅ Safe ~77% | Generic technical text, no vulnerability claim |
| `[flawfinder] Analysis complete. No security issues detected.` | ✅ Safe ~98% | Explicit clean-scan confirmation |

---

## 📊 Model Performance

| Metric | Score |
|---|---|
| Accuracy | **92.05%** |
| Precision | 90.45% |
| Recall | 93.12% |
| F1 Score | **0.9177** |
| ROC AUC | **0.9723** |

> Evaluated on a held-out test set of 4,000+ samples not seen during training.

---

## 🧠 Technical Deep Dive

### Why BERT?

Traditional rule-based systems fail on adversarial inputs:
```python
# Rule-based: WRONG on both
if "strcpy" in log: return "Vulnerable"

# → Marks "[FIXED] strcpy issue" as Vulnerable  ❌
# → Misses "heap memory write past end of buffer" ❌
```

BERT understands *context*. It learns that `strcpy` next to `[PATCHED]` is safe, and that "write past end of buffer" is semantically equivalent to a buffer overflow — even without the word "strcpy."

### Dataset Strategy (20,000+ samples)

| Category | Samples | Purpose |
|---|---|---|
| Real vulnerabilities (buffer overflow, SQLi, XSS, etc.) | 5,000 | Core classification |
| Safe logs (style warnings, clean scans, portability) | 5,000 | Negative class |
| Adversarial examples (patched/resolved issues) | 2,000 | Prevent false positives |
| Semantic variants (same vuln, different phrasing) | 5,000 | Generalization |
| Cross-tool equivalents (Bandit vs Flawfinder vs SonarQube) | 1,500 | Tool-agnostic learning |
| Contextual examples (trust boundaries, attack surface) | 1,500 | Real-world nuance |

### Training Techniques

- **Focal Loss** — Down-weights easy examples; forces the model to focus on ambiguous edge cases
- **Label Smoothing (ε=0.05)** — Prevents overconfidence; produces calibrated probability outputs
- **Class Weighting** — Handles any imbalance between Safe/Vulnerable samples
- **Dropout (p=0.3) + BatchNorm** — Regularization to prevent overfitting

### Confidence Calibration

Raw model outputs are adjusted post-inference based on text signals:

```python
# Security tool + vulnerability keyword + no fix marker → boost confidence
if has_tool_signature and has_vuln_keyword and not has_fix_marker:
    confidence *= 1.15

# Short, generic text with CWE mention → reduce (likely documentation)
if word_count < 15 and is_ambiguous:
    confidence *= 0.75
```

This intelligently reduces alert fatigue without retraining.

---

## 🔌 REST API Reference

### `POST /api/predict`
```json
// Request
{ "log": "./main.c:45: strcpy: Does not check for buffer overflows (CWE-120)" }

// Response
{
  "prediction": "Vulnerable",
  "confidence": 0.923,
  "confidence_level": "HIGH",
  "probabilities": { "safe": 0.077, "vulnerable": 0.923 }
}
```

### `POST /api/batch-predict`
```json
// Request
{ "logs": ["log1...", "log2...", "log3..."] }
```

### `GET /api/health`
```json
{ "status": "healthy", "model_loaded": true, "device": "cuda:0" }
```

---

## 🛠️ Troubleshooting

| Error | Fix |
|---|---|
| `Model file not found` | Run `python improved_vulnerability_classifier.py --train` first |
| `Connection refused :5000` | Make sure `python flask_backend.py` is running in another terminal |
| `ModuleNotFoundError` | Run `pip install torch transformers flask flask-cors` |
| `CUDA out of memory` | Set `BATCH_SIZE = 8` and `MAX_LEN = 128` in the Config class |

---

## 🔭 Future Roadmap

- [ ] **Severity classification** — Critical / High / Medium / Low instead of binary
- [ ] **Explainability** — Highlight which tokens most influenced the prediction (attention visualization)
- [ ] **CI/CD plugin** — GitHub Action that auto-classifies security scan output
- [ ] **Multi-language logs** — Extend to non-English tool outputs
- [ ] **Continuous learning** — Accept user corrections and retrain periodically

---

## 📚 References

- Devlin et al. (2019) — [BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding](https://arxiv.org/abs/1810.04805)
- Lin et al. (2017) — [Focal Loss for Dense Object Detection](https://arxiv.org/abs/1708.02002)
- Vaswani et al. (2017) — [Attention Is All You Need](https://arxiv.org/abs/1706.03762)
- [MITRE CWE Database](https://cwe.mitre.org/)
- [HuggingFace Transformers Documentation](https://huggingface.co/docs/transformers)

---

## 👤 Author

**[Your Name]**  
B.Tech — Artificial Intelligence & Data Science, Year 3  
[LinkedIn](https://linkedin.com/in/vahin-reddy-sathu) • [GitHub](https://github.com/vahin2007) • [Email](vahinsathu@gmail.com)

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
