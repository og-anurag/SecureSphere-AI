"""
SecureSphere AI - Flask frontend.

Thin client over the FastAPI backend (backend/app/main.py). Holds no
user data itself - registration, login, and all scanning happen via
HTTP calls to the backend, which owns the database and JWT auth.
The user's JWT is kept server-side in the Flask session (signed cookie),
never exposed to client-side JS.
"""
import os
import re
from flask import Flask, render_template, request, redirect, session, url_for

import requests
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-insecure-secret-change-me")

UPI_PATTERN = re.compile(r"^[\w.\-]+@[a-zA-Z]+$")


def _auth_headers():
    token = session.get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _classify(text: str) -> str:
    """Very small heuristic classifier - mirrors the Commander agent's logic."""
    text = text.strip()

    if UPI_PATTERN.match(text):
        return "payment"
    if re.search(r"https?://[^\s]+", text) and "\n" not in text and len(text) < 300:
        return "url"
    if any(k in text for k in ["From:", "Subject:", "Reply-To:"]) or ("\n" in text and "@" in text):
        return "email"
    if re.search(r"https?://[^\s]+", text):
        return "url"
    return "unknown"


@app.route("/")
def index():
    if session.get("token"):
        return redirect("/index")
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/perform_registration", methods=["POST"])
def perform_registration():
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        resp = requests.post(
            f"{BACKEND_URL}/auth/register",
            json={"username": name, "email": email, "password": password},
            timeout=10,
        )
    except requests.RequestException:
        return render_template(
            "register.html",
            error_message="Could not reach the security backend. Please try again shortly.",
        )

    if resp.status_code == 200:
        return render_template(
            "login.html",
            message="Registration successful! Kindly proceed to log in.",
        )

    detail = resp.json().get("detail", "Registration failed.") if resp.content else "Registration failed."
    return render_template("register.html", error_message=detail)


@app.route("/perform_login", methods=["POST"])
def perform_login():
    email = request.form.get("users_email")
    password = request.form.get("users_password")

    try:
        resp = requests.post(
            f"{BACKEND_URL}/auth/login",
            json={"email": email, "password": password},
            timeout=10,
        )
    except requests.RequestException:
        return render_template(
            "login.html",
            error_message="Could not reach the security backend. Please try again shortly.",
        )

    if resp.status_code == 200:
        session["token"] = resp.json()["access_token"]
        session["email"] = email
        return redirect("/index")

    return render_template("login.html", error_message="Incorrect email or password.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/index")
def main_page():
    if not session.get("token"):
        return redirect("/")
    return render_template("index.html", email=session.get("email"), report=None, history=None)


@app.route("/submit", methods=["POST"])
def submit():
    if not session.get("token"):
        return redirect("/")

    headers = _auth_headers()
    text_input = (request.form.get("text_input") or "").strip()
    uploaded = request.files.get("file")

    report = None
    error = None

    try:
        if uploaded and uploaded.filename:
            filename = uploaded.filename.lower()
            if filename.endswith(".apk"):
                resp = requests.post(
                    f"{BACKEND_URL}/scan-apk",
                    headers=headers,
                    files={"file": (uploaded.filename, uploaded.stream, uploaded.mimetype)},
                    timeout=30,
                )
                input_type = "apk"
            elif filename.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
                resp = requests.post(
                    f"{BACKEND_URL}/scan-qr",
                    headers=headers,
                    files={"file": (uploaded.filename, uploaded.stream, uploaded.mimetype)},
                    timeout=30,
                )
                input_type = "qr"
            else:
                error = "Unsupported file type. Upload an .apk or an image (.png/.jpg) containing a QR code."
                resp = None
        elif text_input:
            kind = _classify(text_input)
            input_type = kind
            if kind == "url":
                resp = requests.post(f"{BACKEND_URL}/scan-url", headers=headers, json={"url": text_input}, timeout=20)
            elif kind == "payment":
                resp = requests.post(f"{BACKEND_URL}/scan-payment", headers=headers, json={"upi_id": text_input}, timeout=20)
            elif kind == "email":
                # naive split: first line as sender/subject context, rest as body
                lines = text_input.split("\n")
                sender_line = next((l for l in lines if l.lower().startswith("from:")), "")
                subject_line = next((l for l in lines if l.lower().startswith("subject:")), "")
                sender = sender_line.split(":", 1)[-1].strip() or "unknown@unknown.com"
                subject = subject_line.split(":", 1)[-1].strip() or "(no subject)"
                resp = requests.post(
                    f"{BACKEND_URL}/scan-email",
                    headers=headers,
                    json={"sender": sender, "subject": subject, "body": text_input},
                    timeout=20,
                )
            else:
                error = "Couldn't tell what this is. Paste a full URL, a UPI ID (name@bank), or forwarded email text."
                resp = None
        else:
            error = "Paste something to check, or upload a file."
            resp = None

        if resp is not None:
            if resp.status_code == 200:
                report = resp.json()
                report["_input_type"] = input_type
            elif resp.status_code == 401:
                session.clear()
                return redirect("/")
            else:
                error = resp.json().get("detail", "Scan failed.") if resp.content else "Scan failed."

    except requests.RequestException:
        error = "Could not reach the security backend. Please try again shortly."

    return render_template("index.html", email=session.get("email"), report=report, error=error, history=None, active_screen="report" if report else "submit")


@app.route("/dashboard")
def dashboard():
    if not session.get("token"):
        return redirect("/")

    history = None
    try:
        resp = requests.get(f"{BACKEND_URL}/history", headers=_auth_headers(), timeout=15)
        if resp.status_code == 200:
            history = resp.json()
        elif resp.status_code == 401:
            session.clear()
            return redirect("/")
    except requests.RequestException:
        pass

    return render_template("index.html", email=session.get("email"), report=None, history=history, active_screen="dashboard")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
