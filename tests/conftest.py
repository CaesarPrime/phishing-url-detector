import os
import random
import sys
import tempfile

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Keep test databases and models out of the project folder.
_TMP = tempfile.mkdtemp(prefix="phish_tests_")
os.environ.setdefault("DATABASE_URL", "sqlite:///" + os.path.join(_TMP, "import.db"))
os.environ.setdefault("MODELS_DIR", os.path.join(_TMP, "no_models"))
os.environ.setdefault("SECRET_KEY", "test-secret")

LEGIT = ["google.com", "github.com", "wikipedia.org", "nigeria.gov.ng", "ust.edu.ng", "bbc.co.uk",
         "amazon.com", "microsoft.com", "python.org", "stackoverflow.com"]


def synthetic_urls(n=600, seed=1):
    """Small labelled URL set with clear lexical differences (for tests only)."""
    rnd = random.Random(seed)
    urls, labels = [], []
    for _ in range(n // 2):
        urls.append(f"https://www.{rnd.choice(LEGIT)}/{rnd.choice(['', 'about', 'news', 'docs'])}")
        labels.append(0)
        ip = ".".join(str(rnd.randint(1, 254)) for _ in range(4))
        bad = rnd.choice([
            f"http://{ip}/login.php?user=1&id=2",
            f"http://secure-login-verify-account.{rnd.choice(LEGIT)}.xyz.info/update?session=abc",
            f"http://paypal.com@{ip}/signin",
            f"http://account-update-bank-verify.com/confirm_details?id={rnd.randint(1, 999)}",
        ])
        urls.append(bad)
        labels.append(1)
    return urls, labels


@pytest.fixture(scope="session")
def trained_models_dir(tmp_path_factory):
    import joblib
    import pandas as pd
    from sklearn.preprocessing import StandardScaler
    from xgboost import XGBClassifier

    from src.feature_extraction import FEATURE_NAMES, extract_url_features

    urls, labels = synthetic_urls()
    X = pd.DataFrame([extract_url_features(u) for u in urls])[FEATURE_NAMES]
    scaler = StandardScaler()
    Xs = pd.DataFrame(scaler.fit_transform(X), columns=FEATURE_NAMES)
    model = XGBClassifier(n_estimators=30, max_depth=3, eval_metric="logloss")
    model.fit(Xs, labels)

    d = tmp_path_factory.mktemp("models")
    joblib.dump(model, d / "best_phishing_model.pkl")
    joblib.dump(scaler, d / "url_scaler.pkl")
    joblib.dump(FEATURE_NAMES, d / "feature_names.pkl")
    return str(d)


@pytest.fixture()
def client(trained_models_dir, tmp_path):
    from app import create_app

    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "test.db"),
        "MODELS_DIR": trained_models_dir,
    })
    with app.test_client() as c:
        yield c
