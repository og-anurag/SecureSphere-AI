#!/usr/bin/env python3
"""One-pass smoke test for the deployed SecureSphere AI API.

Creates one disposable user per run in the API's users table. It never prints
passwords or access tokens. Run with: python securesphere_smoke_test.py
"""
from __future__ import annotations

import io
import secrets
import time
from datetime import datetime, timezone

import requests

BASE_URL = "https://securesphere-ai-api.onrender.com"
TIMEOUT = 90
results: list[tuple[str, str, str]] = []


def report(name: str, status: str, detail: str = "") -> None:
    results.append((name, status, detail))
    line = f"[{status}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)


def json_response(name: str, response: requests.Response, expected: int = 200) -> dict | None:
    if response.status_code != expected:
        # Deliberately do not print full response bodies; auth responses can contain tokens.
        detail = f"HTTP {response.status_code}"
        try:
            body = response.json()
            if isinstance(body, dict) and isinstance(body.get("detail"), str):
                detail += f": {body['detail'][:160]}"
        except Exception:
            pass
        report(name, "FAIL", detail)
        return None
    try:
        body = response.json()
    except ValueError:
        report(name, "FAIL", "expected JSON response")
        return None
    report(name, "PASS", f"HTTP {response.status_code}")
    return body if isinstance(body, dict) else {"_value": body}


def request_json(session: requests.Session, name: str, method: str, path: str, **kwargs) -> dict | None:
    try:
        response = session.request(method, BASE_URL + path, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        report(name, "FAIL", f"request error: {type(exc).__name__}")
        return None
    return json_response(name, response)


def main() -> int:
    print("SecureSphere AI — live API smoke test")
    print(f"Target: {BASE_URL}")
    print("This creates one disposable smoke-test account. Secrets are not printed.\n")

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})

    # Public/service checks
    health = request_json(session, "Health endpoint", "GET", "/health")
    if health is not None and health.get("status") != "ok":
        report("Health response content", "FAIL", "expected status=ok")
    elif health is not None:
        report("Health response content", "PASS", "status=ok")

    request_json(session, "Home endpoint", "GET", "/")
    request_json(session, "About endpoint", "GET", "/about")

    # Create a unique test user in this run, then login. Values remain in memory only.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    nonce = secrets.token_hex(4)
    username = f"smoke_{stamp}_{nonce}"
    email = f"smoke-{stamp}-{nonce}@example.com"
    password = secrets.token_urlsafe(24)

    registered = request_json(
        session, "Register disposable test account", "POST", "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    token = None
    login = request_json(
        session, "Login with new test account", "POST", "/auth/login",
        json={"email": email, "password": password},
    )
    if login and isinstance(login.get("access_token"), str):
        token = login["access_token"]
        session.headers.update({"Authorization": f"Bearer {token}"})
        report("Login returned access token", "PASS", "token kept private")
    elif login is not None:
        report("Login returned access token", "FAIL", "access_token missing")

    if token:
        me = request_json(session, "Authenticated user lookup", "GET", "/auth/me")
        history = None
    else:
        report("Authenticated user lookup", "SKIP", "login did not return a token")

    # Safe example URL
    url_result = request_json(
        session, "URL scan", "POST", "/scan-url", json={"url": "https://example.com"}
    )
    if url_result is not None:
        report("URL scan result fields", "PASS" if {"risk", "score"} <= set(url_result) else "FAIL",
               f"risk={url_result.get('risk', 'missing')}, score={url_result.get('score', 'missing')}")
        features = url_result.get("features")
        if isinstance(features, dict):
            gsb = features.get("google_safe_browsing")
            if isinstance(gsb, dict) and gsb.get("error") == "no_api_key":
                report("Google Safe Browsing integration", "SKIP", "GOOGLE_SAFE_BROWSING_API_KEY is not configured")

    # Harmless synthetic email; no real email is sent.
    email_result = request_json(
        session, "Email scan", "POST", "/scan-email",
        json={
            "sender": "security-test@example.com",
            "subject": "Routine account notification",
            "body": "This is a harmless test message for checking the SecureSphere AI email scanner. No action is required.",
        },
    )
    if email_result is not None:
        report("Email scan result fields", "PASS" if {"risk", "score"} <= set(email_result) else "FAIL",
               f"risk={email_result.get('risk', 'missing')}, score={email_result.get('score', 'missing')}")

    # Fake UPI identifier; this does not initiate any payment.
    payment_result = request_json(
        session, "Payment identifier scan", "POST", "/scan-payment",
        json={"upi_id": "demo-user@okaxis"},
    )
    if payment_result is not None:
        report("Payment scan result fields", "PASS" if {"risk", "score"} <= set(payment_result) else "FAIL",
               f"risk={payment_result.get('risk', 'missing')}, score={payment_result.get('score', 'missing')}")

    # APK endpoint robustness check with deliberately invalid bytes, not a real APK.
    # This validates error handling only, not detection accuracy on real APK files.
    if token:
        try:
            resp = session.post(
                BASE_URL + "/scan-apk", timeout=TIMEOUT,
                files={"file": ("smoke-invalid.apk", io.BytesIO(b"NOT_A_REAL_APK_TEST_FILE"), "application/vnd.android.package-archive")},
            )
            if resp.status_code == 400:
                # This is the expected safe response for deliberately invalid APK bytes.
                detail = "HTTP 400 expected: invalid APK rejected"
                try:
                    body = resp.json()
                    if isinstance(body, dict) and isinstance(body.get("detail"), str):
                        detail += f" ({body['detail'][:100]})"
                except ValueError:
                    pass
                report("APK endpoint (invalid-file handling only)", "PASS", detail)
            elif resp.status_code == 200:
                apk_body = json_response("APK endpoint (invalid-file handling only)", resp)
                if apk_body is not None:
                    if "risk" in apk_body:
                        report("APK invalid-file verdict", "WARN", f"HTTP 200 for invalid APK; risk={apk_body.get('risk')}")
                    else:
                        report("APK invalid-file verdict", "WARN", "HTTP 200 but no risk field; inspect response schema")
            else:
                # Other status codes are not the expected result for this invalid-file check.
                json_response("APK endpoint (invalid-file handling only)", resp, expected=-1)
        except requests.RequestException as exc:
            report("APK endpoint (invalid-file handling only)", "FAIL", f"request error: {type(exc).__name__}")
    else:
        report("APK endpoint (invalid-file handling only)", "SKIP", "authentication unavailable")

    # Create a real QR image only if the optional local qrcode package is installed.
    if token:
        try:
            import qrcode  # type: ignore
            qr_image = qrcode.make("https://example.com")
            buffer = io.BytesIO()
            qr_image.save(buffer, format="PNG")
            buffer.seek(0)
            try:
                resp = session.post(
                    BASE_URL + "/scan-qr", timeout=TIMEOUT,
                    files={"file": ("smoke-qr.png", buffer, "image/png")},
                )
                qr_result = json_response("QR scan", resp)
                if qr_result is not None:
                    report("QR scan result fields", "PASS" if {"risk", "score"} <= set(qr_result) else "FAIL",
                           f"risk={qr_result.get('risk', 'missing')}, score={qr_result.get('score', 'missing')}")
            except requests.RequestException as exc:
                report("QR scan", "FAIL", f"request error: {type(exc).__name__}")
        except ImportError:
            report("QR scan", "SKIP", "install with: python -m pip install \"qrcode[pil]\"")
        except Exception as exc:
            report("QR scan", "FAIL", f"QR generation/upload error: {type(exc).__name__}")
    else:
        report("QR scan", "SKIP", "authentication unavailable")

    # Agent endpoint uses a harmless prompt and may depend on optional integrations.
    agent_result = request_json(
        session, "Agent analysis", "POST", "/agent/analyze",
        json={"input": "Analyze this harmless security test note: the user visited https://example.com for documentation.", "session_id": f"smoke-{nonce}"},
    )

    if token:
        history = request_json(session, "Authenticated scan history", "GET", "/history")
        if history is not None and "total_scans" in history:
            report("Scan history response fields", "PASS", f"total_scans={history.get('total_scans')}")
    else:
        report("Authenticated scan history", "SKIP", "login did not return a token")

    print("\nSummary")
    counts = {s: sum(1 for _, status, _ in results if status == s) for s in ("PASS", "FAIL", "WARN", "SKIP")}
    print(" | ".join(f"{s}: {counts[s]}" for s in counts))
    print("Note: APK test uses invalid bytes to check safe error handling, not real APK detection.")
    print("Note: this run creates one test user in Neon; no password/token was printed.")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
