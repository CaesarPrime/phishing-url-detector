"""Application configuration. Values can be overridden with environment variables."""

import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Set SECRET_KEY in the environment for any real deployment.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "phishing.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MODELS_DIR = os.environ.get("MODELS_DIR", os.path.join(BASE_DIR, "models"))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True

    MIN_PASSWORD_LENGTH = 6
    HISTORY_PAGE_SIZE = 50
