import os
import sqlite3
import hmac
import ipaddress
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

IS_PRODUCTION = os.environ.get("RENDER") == "true"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

if IS_PRODUCTION:
    if not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 14:
        raise RuntimeError("Set ADMIN_PASSWORD (at least 14 characters) in Render Environment.")
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise RuntimeError("Set FLASK_SECRET_KEY (at least 32 characters) in Render Environment.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY or "local-development-only-change-before-deploy",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    MAX_CONTENT_LENGTH=1024 * 1024,
)
# Render terminates HTTPS at its trusted proxy and forwards the client address.
if IS_PRODUCTION:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "visits.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                page TEXT NOT NULL DEFAULT 'verification'
            )
        """)

init_db()

def get_public_client_ip():
    """Return a validated public client IP from Render's Cloudflare edge header.

    Do not trust arbitrary X-Forwarded-For values: clients can spoof them.
    Render normally provides CF-Connecting-IP at its Cloudflare edge.
    """
    candidates = [request.headers.get("CF-Connecting-IP")]
    if not IS_PRODUCTION:
        candidates.append(request.remote_addr)
    for candidate in candidates:
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate.strip())
        except ValueError:
            continue
        if address.is_global:
            return str(address)
    return "unavailable"

def record_authorized_visit(page="verification"):
    ip = get_public_client_ip()
    user_agent = request.headers.get("User-Agent", "")[:300]
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB) as con:
        con.execute(
            "INSERT INTO visits (created_at, ip_address, user_agent, page) VALUES (?, ?, ?, ?)",
            (created, ip, user_agent, page[:100])
        )

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.route("/", methods=["GET", "POST"])
def verification():
    if request.method == "POST" and request.form.get("agreement") == "yes":
        record_authorized_visit("verification")
        return redirect(url_for("home"))
    return render_template("verification.html")

@app.route("/home")
def home():
    return render_template("index.html")

@app.route("/lab/test-visit", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def test_visit():
    if request.method == "POST" and request.form.get("confirm") == "yes":
        record_authorized_visit("classroom test")
        return render_template("success.html")
    return render_template("test_visit.html")

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        if ADMIN_PASSWORD and hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Incorrect password.")
    return render_template("login.html")

@app.route("/admin/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    return redirect(url_for("verification"))

@app.route("/admin")
@admin_required
def dashboard():
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        visits = con.execute(
            "SELECT id, created_at, ip_address, user_agent, page FROM visits ORDER BY id DESC LIMIT 200"
        ).fetchall()
        total = con.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    return render_template("dashboard.html", visits=visits, total=total)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
