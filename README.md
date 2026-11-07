# Intelligent Hybrid Phishing URL Detection System

A Flask web application that detects phishing website addresses by combining an
**optimized XGBoost machine learning model** with a **cybersecurity rule engine**.
Each scan shows a SAFE/DANGER decision, the model's confidence, a risk level, the
rule score and the security indicators that were triggered. Scans are saved to each
user's history.

> Research project: *Intelligent Hybrid Phishing Uniform Resource Locator Detection
> System Using Machine Learning and Cybersecurity Rules* — Obuzor Mercy Oluka (2026).

## Features

- User registration and login (passwords stored as secure hashes)
- Eleven lexical URL features extracted without visiting the website
- Random Forest, SVM and XGBoost compared; XGBoost tuned with GridSearchCV (5-fold)
- Six weighted cybersecurity rules and a hybrid decision engine
- Confidence score, risk level (LOW / MEDIUM / HIGH) and triggered indicators
- Per-user scan history stored in SQLite
- Training reports: model comparison table, confusion matrix and ROC curve
- Automated tests run on GitHub Actions

## How it works

```
URL ─► validation & normalization ─► 11 lexical features ─┬─► StandardScaler ─► XGBoost ─► prediction + confidence ─┐
                                                          └─► rule engine ─► risk score + triggered rules ───────────┤
                                                                                                                       ▼
                                                                   hybrid decision engine ─► SAFE / DANGER + risk level ─► SQLite history
```

**Hybrid decision rules**
- risk score ≥ 50 → DANGER, whatever the model says
- risk score ≥ 30 and model confidence < 99.5% → DANGER
- otherwise → the model's prediction

| Rule | Condition | Weight |
|---|---|---|
| Numeric IP address | host is an IP address | 50 |
| "@" character | `@` in URL | 40 |
| Long URL | more than 75 characters | 20 |
| Too many subdomains | 5 or more dots | 20 |
| Multiple hyphens | 3 or more hyphens | 15 |
| No HTTPS | scheme is not https | 10 |

Risk level: 0–19 LOW, 20–49 MEDIUM, 50+ HIGH.

## Project structure

```
phishing-url-detector/
├── app.py                    # Flask application (routes, login, scanning, history)
├── config.py                 # Settings (secret key, database, model folder)
├── train_pipeline.py         # Trains, compares, tunes and saves the model
├── requirements.txt
├── src/
│   ├── feature_extraction.py # 11 lexical URL features
│   ├── rule_engine.py        # Cybersecurity rules
│   ├── hybrid_engine.py      # Hybrid decision and risk level
│   ├── predictor.py          # Loads the model and analyses a URL
│   ├── url_utils.py          # URL normalization and validation
│   └── models.py             # Database tables: users, scan_history
├── templates/                # HTML pages (Bootstrap 5)
├── static/css/style.css
├── data/                     # Put phishing_dataset.csv here (see data/README.md)
├── models/                   # Trained model files are saved here
├── reports/                  # Comparison table, confusion matrix, ROC curve
└── tests/                    # Automated tests (pytest)
```

## Installation

Requirements: **Python 3.10 or later** and Git.

```bash
git clone https://github.com/<your-username>/phishing-url-detector.git
cd phishing-url-detector

python -m venv venv
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

pip install -r requirements.txt
```

## 1. Get the dataset

Download the PhiUSIIL Phishing URL Dataset, rename it to `phishing_dataset.csv` and put it in
the `data/` folder. Full instructions are in [`data/README.md`](data/README.md).

## 2. Train the model

```bash
python train_pipeline.py
```

This samples 50,000 URLs, compares the three algorithms, tunes XGBoost and saves:

- `models/best_phishing_model.pkl`, `url_scaler.pkl`, `feature_names.pkl`, `model_metadata.json`
- `reports/model_comparison_results.csv`, `confusion_matrix.png`, `roc_curve.png`

Options: `--sample 0` uses the whole dataset; `--skip-svm` skips the slow SVM.
Training takes a few minutes on a normal laptop (SVM is the slowest step).

**Class encoding:** inside this project **1 = phishing** and **0 = legitimate**, so precision,
recall and F1-score are reported for the phishing class. PhiUSIIL uses the opposite labels
(0 = phishing); `train_pipeline.py` converts them automatically.

## 3. Run the application

```bash
python app.py
```

Open **http://127.0.0.1:5000**, register an account, log in and scan a URL. The SQLite database
(`phishing.db`) is created automatically.

For a real deployment, set a fixed secret key and use a production server:

```bash
# macOS / Linux
export SECRET_KEY="a-long-random-string"
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:8000 app:app

# Windows
set SECRET_KEY=a-long-random-string
pip install waitress
waitress-serve --port=8000 app:app
```

## Run the tests

```bash
pytest -q
```

The tests train a tiny model on synthetic URLs, so they do not need the dataset.

## Uploading to GitHub

1. Create an empty repository on GitHub named `phishing-url-detector` (no README).
2. In the project folder run:

```bash
git init
git add .
git commit -m "Intelligent hybrid phishing URL detection system"
git branch -M main
git remote add origin https://github.com/<your-username>/phishing-url-detector.git
git push -u origin main
```

The dataset and the local database are excluded by `.gitignore`. To let visitors run the app
without training, you can also commit the trained files in `models/` (they are small):
`git add -f models/*.pkl models/model_metadata.json`.

## Limitations

- Only the URL text is analysed; webpage content, WHOIS, DNS and SSL certificates are not checked.
- The model reflects the dataset it was trained on and should be retrained periodically.
- The rule set is fixed and needs updating as phishing techniques change.

## Reference

Prasad, A., & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL
detection framework based on similarity index and incremental learning. *Computers & Security, 136*, 103545.
