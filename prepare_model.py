"""Downloads the PhiUSIIL dataset and trains the model if no trained model exists.
Used as part of the build command on hosting services such as Render."""
import io
import os
import subprocess
import sys
import urllib.request
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(BASE, "models", "best_phishing_model.pkl")
DATA = os.path.join(BASE, "data", "phishing_dataset.csv")
URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"

if os.path.exists(MODEL):
    print("Trained model found - skipping training.")
    sys.exit(0)

if not os.path.exists(DATA):
    print("Downloading PhiUSIIL dataset...")
    raw = urllib.request.urlopen(URL, timeout=600).read()
    archive = zipfile.ZipFile(io.BytesIO(raw))
    csv_name = [n for n in archive.namelist() if n.lower().endswith(".csv")][0]
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    with open(DATA, "wb") as fh:
        fh.write(archive.read(csv_name))
    print("Dataset saved.")

print("Training model...")
subprocess.check_call([sys.executable, os.path.join(BASE, "train_pipeline.py"), "--skip-svm"])
