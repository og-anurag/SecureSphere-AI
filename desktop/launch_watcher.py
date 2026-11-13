from getpass import getpass
from pathlib import Path
import os
import subprocess
import sys
import time

import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = "http://127.0.0.1:8000"

sys.path.insert(0, str(ROOT))
from desktop import watcher


def backend_healthy(url):
    try:
        response = requests.get(url.rstrip("/") + "/health", timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False


def start_backend():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "backend")

    try:
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            cwd=str(ROOT),
            env=env,
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
        )
    except OSError as exc:
        print(f"Could not start backend: {exc}")
        return False

    for _ in range(30):
        if backend_healthy(DEFAULT_URL):
            return True
        time.sleep(1)

    return False


def main():
    url = os.getenv("SECURESPHERE_BACKEND_URL", DEFAULT_URL).rstrip("/")
    watcher.BACKEND_URL = url
    watcher.SECURESPHERE_TOKEN = ""

    print("SecureSphere AI Desktop Launcher")
    print("=" * 34)

    if not backend_healthy(url):
        print("Backend is not responding.")

        if url not in (DEFAULT_URL, "http://localhost:8000"):
            print("Check SECURESPHERE_BACKEND_URL.")
        else:
            choice = input("Start the local backend now? [Y/n]: ").strip().lower()

            if choice not in ("n", "no"):
                if start_backend():
                    print("Backend started successfully.")
                else:
                    print("Backend could not be started.")
                    print("Continuing with local-only APK scanning.")
            else:
                print("Continuing with local-only APK scanning.")

    if backend_healthy(url):
        email = input(
            "SecureSphere account email (Enter for local-only mode): "
        ).strip()

        if email:
            password = getpass("Password: ")

            try:
                response = requests.post(
                    url + "/auth/login",
                    json={"email": email, "password": password},
                    timeout=15,
                )
                if response.status_code != 200:
                    print(f"Login failed: HTTP {response.status_code}")
                    return 1

                token = response.json().get("access_token")
                if not token:
                    print("Login response did not contain an access token.")
                    return 1

                watcher.SECURESPHERE_TOKEN = token
                print("Backend APK authentication configured.")
            except (requests.RequestException, ValueError) as exc:
                print(f"Login failed: {exc}")
                return 1
        else:
            print("Local-only APK scanning selected.")

    try:
        watcher.run_watcher()
    except KeyboardInterrupt:
        print("\nSecureSphere AI Desktop Watcher stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())