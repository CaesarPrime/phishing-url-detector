"""
Intelligent Hybrid Phishing URL Detection System
================================================

Flask web application: registration, login, URL scanning with the hybrid
(XGBoost + cybersecurity rules) detector, and scan history.

Run:  python app.py      then open http://127.0.0.1:5000
"""

import logging
import os
import re

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (LoginManager, current_user, login_required, login_user,
                         logout_user)

from config import Config
from src.models import ScanHistory, User, db
from src.predictor import ModelNotTrainedError, PhishingDetector
from src.url_utils import is_valid_url, normalize_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("phishing_app")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Please log in to use the phishing URL scanner."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    with app.app_context():
        db.create_all()

    # Load the trained model once at start-up.
    try:
        app.detector = PhishingDetector(app.config["MODELS_DIR"])
        app.model_error = None
    except ModelNotTrainedError as exc:
        app.detector = None
        app.model_error = str(exc)
        logger.error(app.model_error)

    # ------------------------------------------------------------------ AUTH
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not USERNAME_RE.match(username):
                flash("Username must be 3-30 characters: letters, numbers, '.', '_' or '-'.", "danger")
            elif len(password) < app.config["MIN_PASSWORD_LENGTH"]:
                flash(f"Password must be at least {app.config['MIN_PASSWORD_LENGTH']} characters.", "danger")
            elif password != confirm:
                flash("Passwords do not match.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("That username is already taken.", "danger")
            else:
                user = User(username=username)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                logger.info("New user registered: %s", username)
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                logger.info("User logged in: %s", username)
                next_page = request.args.get("next", "")
                if not next_page.startswith("/") or next_page.startswith("//"):
                    next_page = url_for("index")
                return redirect(next_page)
            logger.warning("Failed login attempt for username: %s", username)
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ SCANNER
    @app.route("/", methods=["GET", "POST"])
    @login_required
    def index():
        result = None
        submitted = ""
        if request.method == "POST":
            submitted = request.form.get("url", "")
            if app.detector is None:
                flash("The detection model is not available. Train the model first (see README).", "danger")
                return render_template("index.html", result=None, submitted=submitted)

            if not submitted.strip():
                flash("Please enter a URL.", "danger")
                return render_template("index.html", result=None, submitted=submitted)

            input_url = normalize_url(submitted)
            if not is_valid_url(input_url):
                logger.warning("Invalid URL submitted: %s", submitted)
                flash("Please enter a valid web address, e.g. https://www.example.com", "danger")
                return render_template("index.html", result=None, submitted=submitted)

            try:
                result = app.detector.analyze(input_url)
                db.session.add(ScanHistory(
                    user_id=current_user.id,
                    scanned_url=input_url,
                    prediction=result["label"],
                    confidence=result["confidence"],
                    risk_level=result["risk_level"],
                    rule_score=result["risk_score"],
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("Prediction pipeline failed.")
                flash("An unexpected error occurred while analysing the URL.", "danger")
                result = None
        return render_template("index.html", result=result, submitted=submitted)

    @app.route("/history")
    @login_required
    def history():
        scans = (ScanHistory.query.filter_by(user_id=current_user.id)
                 .order_by(ScanHistory.scan_date.desc())
                 .limit(app.config["HISTORY_PAGE_SIZE"]).all())
        return render_template("history.html", scans=scans)

    @app.route("/about")
    def about():
        meta = app.detector.metadata if app.detector else {}
        return render_template("about.html", meta=meta, model_error=app.model_error)

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(_):
        return render_template("error.html", code=500, message="Internal server error."), 500

    return app


app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=debug)
