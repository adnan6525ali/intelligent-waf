# Intelligent Web Application Firewall Using Deep Learning for Zero-Day Attack Detection

## Project Overview

This project presents an intelligent Web Application Firewall (WAF) for detecting malicious web traffic, including previously unseen or zero-day attack patterns, using deep learning. The work combines sequence-based and attention-based neural architectures to analyze HTTP request behavior and classify requests as benign or malicious.

The project is developed as an M.Tech cybersecurity academic project and includes:

- Exploratory data analysis and preprocessing pipelines
- Deep learning models built with PyTorch
- A Flask-based WAF prototype for inference
- Comparative benchmarking against ModSecurity
- Evaluation artifacts such as metrics and plots

## Objectives

- Design an intelligent WAF capable of identifying malicious HTTP requests beyond static signature-based rules
- Explore deep learning approaches for web attack detection using sequential request data
- Train and compare LSTM, Bi-LSTM, and Transformer-based models
- Evaluate model effectiveness on benchmark cybersecurity datasets
- Build a Flask prototype to simulate real-time firewall decision-making
- Compare the learning-based approach with ModSecurity as a traditional baseline

## Tech Stack

| Category | Tools / Libraries |
| --- | --- |
| Programming Language | Python |
| Deep Learning | PyTorch |
| Models | LSTM, Bi-LSTM, Transformer |
| Data Handling | Pandas, NumPy |
| Machine Learning Utilities | Scikit-learn |
| Visualization | Matplotlib, Seaborn |
| Web Prototype | Flask |
| Baseline WAF | ModSecurity |
| Datasets | CSIC 2010 HTTP Dataset, CICIDS 2018 |
| Experimentation | Jupyter Notebooks |

## Folder Structure

```text
WAF-DeepLearning/
├── data/
│   ├── raw/
│   ├── processed/
│   └── splits/
├── notebooks/
│   ├── 01_EDA.ipynb
│   ├── 02_Preprocessing.ipynb
│   ├── 03_LSTM_Model.ipynb
│   ├── 04_BiLSTM_Model.ipynb
│   └── 05_Transformer_Model.ipynb
├── models/
├── firewall/
│   ├── app.py
│   ├── predict.py
│   └── templates/
├── results/
│   ├── metrics.csv
│   └── plots/
└── report/
```

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd WAF-DeepLearning
```

### 2. Create and Activate a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

For Windows:

```bash
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install torch flask pandas numpy scikit-learn matplotlib seaborn jupyter notebook
```

If you are using GPU acceleration, install the PyTorch build compatible with your CUDA version from the official PyTorch installation guide.

### 4. Prepare the Datasets

- Download the CSIC 2010 HTTP dataset and CICIDS 2018 dataset
- Place the original files inside `data/raw/`
- Use the preprocessing notebook to clean, tokenize, encode, and split the data
- Store processed outputs inside `data/processed/` and train/validation/test splits inside `data/splits/`

### 5. Run the Notebooks

Execute the notebooks in order:

1. `01_EDA.ipynb`
2. `02_Preprocessing.ipynb`
3. `03_LSTM_Model.ipynb`
4. `04_BiLSTM_Model.ipynb`
5. `05_Transformer_Model.ipynb`

### 6. Run the Flask Firewall Prototype

```bash
python firewall/app.py
```

The Flask application can be used to test incoming request payloads and generate model-based predictions for malicious or benign classification.

### 7. ModSecurity Comparison

Install and configure ModSecurity separately in your web server environment if you want to perform baseline comparisons against a signature-based WAF.

## Datasets Used

### 1. CSIC 2010 HTTP Dataset

The CSIC 2010 dataset is a benchmark dataset for web application attack detection. It contains legitimate and malicious HTTP requests targeting web applications. It is useful for training sequence models to learn request-level attack patterns such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Parameter Tampering

### 2. CICIDS 2018

The CICIDS 2018 dataset contains modern network intrusion traffic with a wide range of benign and attack scenarios. In this project, it can be used to enrich the experimental setup with broader intrusion patterns and validate model generalization.

## Models

### 1. LSTM

The LSTM model serves as a sequential baseline for learning temporal dependencies in tokenized HTTP request data.

### 2. Bi-LSTM

The Bi-LSTM model captures contextual information from both forward and backward directions in a request sequence, improving representation quality for attack classification.

### 3. Transformer

The Transformer model uses self-attention mechanisms to capture long-range dependencies and contextual relationships in web request sequences, making it well suited for zero-day attack detection scenarios.

## Evaluation Metrics

The project evaluates model performance using standard classification metrics:

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix
- ROC-AUC

These metrics help assess both overall performance and the model's ability to minimize false positives and false negatives, which is critical in firewall deployment.

## Results

Experimental outputs should be stored in the `results/` directory, including:

- `metrics.csv` for consolidated model evaluation metrics
- `plots/` for confusion matrices, loss curves, accuracy curves, ROC curves, and comparison charts

The expected analysis includes:

- Performance comparison between LSTM, Bi-LSTM, and Transformer models
- Comparison of the deep learning-based WAF against ModSecurity
- Discussion of generalization capability for detecting previously unseen attack patterns
- Trade-off analysis between detection accuracy, false alarms, and deployment practicality

Note: The current repository structure includes placeholders for result artifacts. Update this section with final experimental values after model training and evaluation are completed.

## References

1. CSIC 2010 HTTP Dataset
2. CICIDS 2018 Dataset
3. PyTorch Documentation
4. Flask Documentation
5. ModSecurity Documentation
6. Research literature on deep learning-based intrusion detection and web attack detection

## License

This repository is intended for academic and research purposes as part of an M.Tech cybersecurity project.
