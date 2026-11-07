"""Database models (SQLite through SQLAlchemy)."""

from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)

    scans = db.relationship("ScanHistory", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scanned_url = db.Column(db.Text, nullable=False)
    prediction = db.Column(db.String(10), nullable=False)      # SAFE or DANGER
    confidence = db.Column(db.Float, nullable=False)           # 0.0 - 1.0
    risk_level = db.Column(db.String(10), nullable=False)      # LOW, MEDIUM or HIGH
    rule_score = db.Column(db.Integer, nullable=False)
    scan_date = db.Column(db.DateTime, default=_now, nullable=False)
