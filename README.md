# 🛡️ AI-Driven Vulnerability Classifier (NLP4SE)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge) ![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white) ![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-F9AB00?style=for-the-badge&logo=huggingface&logoColor=white) ![DevSecOps](https://img.shields.io/badge/AppSec-Shift--Left-red?style=for-the-badge)

An enterprise-grade Machine Learning security pipeline designed to autonomously parse, cluster, and classify raw C/C++ compiler error logs and static analysis outputs into safe anomalies or high-risk security vulnerabilities.

### 🧠 Core Architecture
This pipeline abandons traditional, brittle Regex/Feature-Engineering approaches in favor of pure semantic understanding:
* **Deep Learning NLP:** Fine-tuned a **BERT** architecture (`bert-base-uncased`) via HuggingFace to convert unstructured error text into dense vector embeddings, capturing deep semantic relationships between syntax failures and security flaws.
* **Context-Aware Classification:** The model is trained to understand trust boundaries, attack surfaces, and temporal contexts (e.g., recognizing that a compiler error is a safe build failure, while a runtime memory leak is an exploitable vulnerability).
* **Calibrated Inference:** Implements a custom confidence calibration engine to reduce false positives, dynamically adjusting certainty based on ambiguity scores and tool-specific vulnerability markers.

### 📊 Synthetic & Adversarial Data Engine
Traditional ML security models fail on edge cases. This repository includes a custom, highly modular `data_generator.py` that synthesizes a massive, 5,000+ sample semantic dataset. 
It trains the model to understand:
* **Adversarial Safety:** Logs that *sound* dangerous but are actually defensive mechanisms (e.g., `ASSERT FAILED: buffer_size > 0`).
* **Semantic Equivalents:** Grouping different tool outputs (AddressSanitizer, Valgrind, Checkmarx) that describe the exact same underlying CWE.
* **Compound Vulnerabilities:** Recognizing chained exploits and mitigation contexts.

---

### 🚀 Usage & Command-Line Interface (CLI)

**1. Install Dependencies**
```bash
pip install -r requirements.txt

Pipeline Orchestration
The entire pipeline is orchestrated through main.py. Use the following flags to execute different phases of the system:

Execution Command,System Action
python main.py --train,"Generates the 5,000+ sample semantic dataset, creates train/val/test splits, and initiates the PyTorch optimization loop. Saves the best model weights to the /models directory."
python main.py --test,"Loads the most recent optimized weights and evaluates the model against the unseen test split. Outputs a full classification report (Precision, Recall, F1, ROC AUC)."
python main.py --interactive,Initializes the inference engine in your terminal. Allows you to paste raw compiler or SAST tool logs and receive real-time vulnerability classifications and calibrated confidence scores.
python main.py --diagnostic,Runs a baseline feature-leakage test to ensure the BERT model is learning pure semantic representations rather than memorizing hardcoded artifacts.