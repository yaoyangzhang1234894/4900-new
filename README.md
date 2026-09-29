AI-Driven Phishing Detection System

 An end-to-end ML system that detects phishing emails, malicious URLs, and suspicious PDF attachments — with explainable AI built in.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?logo=scikitlearn&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-Ensemble-189FDD?logo=xgboost&logoColor=white)
![LIME + SHAP](https://img.shields.io/badge/XAI-LIME%20%2B%20SHAP-FF6F00)
![Flask](https://img.shields.io/badge/Flask-REST%20API-000000?logo=flask&logoColor=white)
![PyMuPDF](https://img.shields.io/badge/PyMuPDF-PDF%20Analysis-8B00FF)
![Last Commit](https://img.shields.io/github/last-commit/yaoyangzhang1234894/4900-new?color=blue)
![Repo Size](https://img.shields.io/github/repo-size/yaoyangzhang1234894/4900-new?color=orange)
![License](https://img.shields.io/badge/License-Educational-lightgrey)

---

 Demo

View Running Screenshots：https://drive.google.com/drive/folders/1_0riltn7HN9e_YPxM2-4_FSTtAEt7QZZ?usp=sharing

The screenshots show:
 - Email content analysis with prediction & accuracy
 - Extracted URLs and their classification results
 - LIME explanation (word-level importance)
 - Similar links analysis (SHAP)
 - Final combined output

---

What It Does

Email Analysis: Detects phishing content using TF-IDF + stacking ensemble 
URL Detection: 30+ engineered features + ML classifier for malicious links 
File Analysis: Scans PDFs for JavaScript, macros, and high entropy 
Explainable AI: LIME & SHAP show 'why' a prediction was made
Case-Based Reasoning: Compares links to a known phishing database via cosine similarity 

---

Tech Stack

Backend: Python · Flask · scikit-learn · XGBoost · LightGBM  
NLP / XAI: TF-IDF · LIME · SHAP · NLTK  
File Parsing: PyMuPDF · BeautifulSoup  
Frontend: HTML · JavaScript · Flask-CORS

---

Quick Start

1. Clone (with Git LFS for models)
git lfs install
git clone https://github.com/yaoyangzhang1234894/4900-new.git
cd 4900-new

2. Install dependencies
pip install flask flask-cors joblib numpy pandas "scikit-learn==1.5.2" \
            scipy beautifulsoup4 lxml nltk tldextract requests \
            python-whois dnspython lime shap matplotlib PyMuPDF \
            python-docx openpyxl xgboost lightgbm catboost dill

3. Download datasets (data/ folder)
 https://drive.google.com/drive/folders/1SAw_F3G67uf9VNxf-EVJ7ZRDaV5S_5LY
Place all files inside data/.

# 4. Run
python app.py
Then open webapplication.html in your browser.

Highlights
Stacking ensemble combining Logistic Regression, Random Forest, KNN, MLP, XGBoost, and Gradient Boosting

Explainability via LIME (word importance) and SHAP (similar-link analysis)

Parallel processing with ThreadPoolExecutor for URL scoring (DB + CBR + ML in parallel)

End-to-end pipeline from raw .eml file → phishing verdict

Team
Yaoyang Zhang · Haoxin Zeng· Nassim


