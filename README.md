# 🛡️ SecureSphere AI

**Multi-Agent AI-Powered Digital Security Assistant**

SecureSphere AI is a cybersecurity project that combines specialized scanning components to help identify potential phishing, malware, QR-code and payment fraud risks. It provides scan results, risk assessments and security recommendations.

> SecureSphere AI is an evolving security prototype. Scan results are not a guarantee that a file, website or message is safe.

## 🚀 Features

- **Website Security:** URL analysis and phishing-risk detection.
- **Email Security:** Scam and suspicious-email analysis.
- **APK Analysis:** APK inspection and suspicious-permission heuristics.
- **QR Code Security:** QR-related threat analysis.
- **Payment Security:** Payment and UPI-related risk checks.
- **Risk Analysis:** Unified scan results and security recommendations.
- **Authentication:** Protected backend endpoints and JWT-based authentication.
- **Scan History:** Store and retrieve previous scan results.
- **Browser Extension:** Automatic URL checks, risk indicators and warning pages for high-risk results.
- **Desktop Protection:** Monitor new files in the user's Downloads folder. APKs use the SecureSphere scanner; other monitored file types use Windows Defender when available.
- **Web Dashboard:** Access scanning and security-related information.

## 🏗️ Architecture

```text
User / Browser / Desktop
          |
          v
     SecureSphere API
          |
          v
     Scan Coordination
          |
   +------+------+------+------+
   |      |      |      |      |
  URL   Email   APK    QR   Payment
   |      |      |      |      |
   +------+------+------+------+
                 |
                 v
          Risk Assessment
                 |
                 v
      Findings and Recommendations
                 |
                 v
       Scan History / Dashboard
```

The project uses specialized scanning components and LangGraph-based coordination. Scanning coverage and confidence depend on the component and available integrations.

## 🛠️ Technology Stack

- **Language:** Python, JavaScript
- **Backend:** FastAPI
- **AI Coordination:** LangGraph
- **Database:** SQLite by default, SQLAlchemy and Alembic for ORM and migrations
- **Security Analysis:** URL, email, APK, QR and payment scanning components
- **Browser:** Chrome Extension, Manifest V3
- **Desktop:** Python watcher and Windows Defender integration
- **Dashboard:** Web-based frontend
- **Testing:** pytest
- **Containerization:** Dockerfile included; deployment must be validated in the target environment

## 📂 Project Structure

```text
SecureSphere-AI/
├── agents/                 # Agent graph and coordination
├── backend/                # API, scanners, authentication and tests
├── desktop/                # Windows desktop watcher and launcher
├── docs/                   # Setup and usage documentation
├── extension/              # Chrome browser extension
├── frontend/               # Web dashboard
├── assets/
├── datasets/
├── screenshots/
├── tests/
├── Dockerfile
├── alembic.ini
├── requirements.txt
├── README.md
└── .gitignore
```

## ⚙️ Setup — Windows

### 1. Install dependencies

Open CMD in the repository directory:

```cmd
python -m pip install -r requirements.txt -r backend\requirements.txt
```

### 2. Configure the environment

Create or update the root `.env` file. Set `SECRET_KEY` to a secure value containing at least 32 characters. Configure any optional threat-intelligence API keys you intend to use.

Do not commit `.env` or expose passwords, API keys or access tokens.

### 3. Apply database migrations

```cmd
set PYTHONPATH=backend && python -m alembic upgrade head
```

### 4. Start the backend

```cmd
set PYTHONPATH=backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Check that the API responds:

```cmd
curl http://127.0.0.1:8000/health
```

### 5. Start desktop protection

In a separate CMD window:

```cmd
desktop\start_watcher.bat
```

The launcher can start the local backend if it is not responding and can authenticate against a SecureSphere account for backend APK scanning.

See **[Windows Desktop Setup](docs/windows-desktop-setup.md)** for complete instructions, scan-result meanings and troubleshooting.

## 🧪 Testing

Run the backend test suite from the repository root:

```cmd
set PYTHONPATH=backend && python -m pytest backend\tests -q
```

## 🔐 Important Security Notes

- An **Unknown** APK result means analysis was inconclusive; it does not mean the APK is safe.
- An **Unverified** Defender result means the scan outcome could not be confirmed.
- A Defender clean result does not guarantee that a file is harmless.
- The current desktop watcher reports scan outcomes; it does not itself quarantine files or guarantee that threats are blocked.
- The watcher monitors newly appearing files in the top-level Downloads folder. It does not recursively scan every directory or automatically scan all existing files at startup.

## 🗺️ Roadmap

- [x] Repository created
- [x] Project structure established
- [x] Core backend scanning endpoints
- [x] Authentication and scan history
- [x] Risk-result coordination
- [x] Chrome extension URL scanning and warning flow
- [x] APK parser-failure handling
- [x] Windows Defender scanning for monitored non-APK files
- [x] One-click Windows desktop launcher
- [x] Desktop watcher regression tests
- [x] Windows desktop setup documentation
- [ ] Package the desktop application into an installer
- [ ] Validate container build and deployment in a target environment
- [ ] Expand desktop monitoring, remediation and user controls
- [ ] Continue improving dashboard and extension usability
- [ ] Evaluate and develop a dedicated Android application

## 📜 License

See the [LICENSE](LICENSE) file for license terms.