"""
Machine Learning Training Pipeline
==================================

1. Load the phishing URL dataset (PhiUSIIL by default) and draw a random sample
2. Extract the eleven lexical features from each URL
3. Split 80:20 (stratified) and standardize the features
4. Train and compare Random Forest, SVM and XGBoost
5. Optimize XGBoost with GridSearchCV (5-fold, F1)
6. Evaluate the optimized model and save the model, scaler, feature names,
   metadata, comparison table, confusion matrix and ROC curve

Class convention: 1 = PHISHING, 0 = LEGITIMATE.
The PhiUSIIL dataset labels phishing URLs as 0 and legitimate URLs as 1,
so the labels are converted here (see PHISHING_LABEL_VALUE).

Usage:
    python train_pipeline.py
    python train_pipeline.py --data data/phishing_dataset.csv --sample 50000
"""

import argparse
import json
import logging
import os
from datetime import datetime

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score, auc,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_curve)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier

from src.feature_extraction import FEATURE_NAMES, extract_url_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("train_pipeline")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_DATA = os.path.join(BASE_DIR, "data", "phishing_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

URL_COLUMN = "URL"
LABEL_COLUMN = "label"
PHISHING_LABEL_VALUE = 0      # PhiUSIIL: 0 = phishing, 1 = legitimate
RANDOM_STATE = 42


def parse_args():
    p = argparse.ArgumentParser(description="Train the phishing URL detection model.")
    p.add_argument("--data", default=DEFAULT_DATA, help="CSV file with URL and label columns")
    p.add_argument("--sample", type=int, default=50000, help="number of URLs to sample (0 = use all)")
    p.add_argument("--url-column", default=URL_COLUMN)
    p.add_argument("--label-column", default=LABEL_COLUMN)
    p.add_argument("--phishing-value", default=PHISHING_LABEL_VALUE,
                   help="value of the label column that means PHISHING (PhiUSIIL: 0)")
    p.add_argument("--skip-svm", action="store_true", help="skip the (slow) SVM in the comparison")
    return p.parse_args()


def evaluate(y_true, y_pred):
    return {
        "Accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "Precision": round(float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "Recall": round(float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "F1 Score": round(float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
    }


def main():
    args = parse_args()
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------ 1. LOAD
    if not os.path.exists(args.data):
        raise SystemExit(f"Dataset not found: {args.data}\nSee data/README.md for download instructions.")
    logger.info("Loading dataset: %s", args.data)
    df = pd.read_csv(args.data, usecols=[args.url_column, args.label_column])
    df = df.dropna().drop_duplicates(subset=[args.url_column]).reset_index(drop=True)
    original_size = len(df)
    logger.info("Dataset size after removing missing values and duplicates: %d", original_size)

    if args.sample and len(df) > args.sample:
        df = df.sample(n=args.sample, random_state=RANDOM_STATE).reset_index(drop=True)
        logger.info("Randomly sampled %d records.", len(df))

    phishing_value = type(df[args.label_column].iloc[0])(args.phishing_value)
    y = (df[args.label_column] == phishing_value).astype(int)     # 1 = phishing
    logger.info("Class distribution: phishing=%d, legitimate=%d", int(y.sum()), int((y == 0).sum()))
    if y.nunique() != 2:
        raise SystemExit("Both phishing and legitimate URLs are required. Check --phishing-value.")

    # ------------------------------------------------------------ 2. FEATURES
    logger.info("Extracting lexical features...")
    X = pd.DataFrame([extract_url_features(u) for u in df[args.url_column]])[FEATURE_NAMES]
    joblib.dump(FEATURE_NAMES, os.path.join(MODELS_DIR, "feature_names.pkl"))

    # ------------------------------------------------------------ 3. SPLIT + SCALE
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y)
    logger.info("Training samples: %d | Testing samples: %d", len(X_train), len(X_test))

    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_NAMES)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_NAMES)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "url_scaler.pkl"))

    # ------------------------------------------------------------ 4. COMPARE MODELS
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1),
        "Support Vector Machine": SVC(kernel="rbf", C=1.0, probability=True, random_state=RANDOM_STATE),
        "XGBoost": XGBClassifier(n_estimators=100, learning_rate=0.10, random_state=RANDOM_STATE,
                                 eval_metric="logloss", n_jobs=-1),
    }
    if args.skip_svm:
        models.pop("Support Vector Machine")

    rows = []
    for name, model in models.items():
        logger.info("Training %s ...", name)
        model.fit(X_train_s, y_train)
        scores = evaluate(y_test, model.predict(X_test_s))
        rows.append({"Model": name, **scores})
        logger.info("%s: %s", name, scores)
    comparison = pd.DataFrame(rows)
    comparison.to_csv(os.path.join(REPORTS_DIR, "model_comparison_results.csv"), index=False)
    print("\nMODEL COMPARISON (positive class = phishing)\n" + comparison.to_string(index=False) + "\n")

    # ------------------------------------------------------------ 5. GRID SEARCH
    logger.info("Starting GridSearchCV for XGBoost...")
    grid = GridSearchCV(
        estimator=XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1),
        param_grid={"n_estimators": [50, 100], "max_depth": [3, 5], "learning_rate": [0.10, 0.20]},
        cv=5, scoring="f1", n_jobs=-1, verbose=1)
    grid.fit(X_train_s, y_train)
    best_model = grid.best_estimator_
    logger.info("Best parameters: %s | Best CV F1: %.4f", grid.best_params_, grid.best_score_)

    # ------------------------------------------------------------ 6. FINAL EVALUATION
    y_pred = best_model.predict(X_test_s)
    y_prob = best_model.predict_proba(X_test_s)[:, 1]
    final = evaluate(y_test, y_pred)
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = round(float(auc(fpr, tpr)), 4)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    disp = ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Greys", values_format="d")
    plt.title("Confusion Matrix of the Optimized XGBoost Model")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "confusion_matrix.png"), dpi=200)
    plt.close()

    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color="black", label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], color="grey", linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "roc_curve.png"), dpi=200)
    plt.close()

    joblib.dump(best_model, os.path.join(MODELS_DIR, "best_phishing_model.pkl"))
    metadata = {
        "Project": "Intelligent Hybrid Phishing URL Detection System",
        "Algorithm": "Optimized XGBoost",
        "Training Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Class Encoding": {"0": "Legitimate", "1": "Phishing"},
        "Original Dataset Size": int(original_size),
        "Dataset Size": int(len(df)),
        "Training Samples": int(len(X_train)),
        "Testing Samples": int(len(X_test)),
        "Number of Features": len(FEATURE_NAMES),
        "Feature Names": FEATURE_NAMES,
        "Best Parameters": grid.best_params_,
        "Validation F1": round(float(grid.best_score_), 4),
        **final,
        "ROC AUC": roc_auc,
        "Confusion Matrix": {"TN": int(cm[0, 0]), "FP": int(cm[0, 1]), "FN": int(cm[1, 0]), "TP": int(cm[1, 1])},
    }
    with open(os.path.join(MODELS_DIR, "model_metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=4)

    print("=" * 70)
    print("TRAINING PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 70)
    for k in ("Accuracy", "Precision", "Recall", "F1 Score"):
        print(f"{k:<10}: {final[k]:.4f}")
    print(f"ROC AUC   : {roc_auc:.4f}")
    print(f"Confusion matrix (TN, FP, FN, TP): {metadata['Confusion Matrix']}")
    print("Saved: models/best_phishing_model.pkl, url_scaler.pkl, feature_names.pkl, model_metadata.json")
    print("Saved: reports/model_comparison_results.csv, confusion_matrix.png, roc_curve.png")


if __name__ == "__main__":
    main()
