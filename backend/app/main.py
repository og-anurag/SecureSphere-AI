from fastapi import FastAPI
from app.routes import url_scan, email_scan, apk_scan, auth


app = FastAPI(
    title="SecureSphere AI API",
    description="AI-powered cybersecurity API for URL, email, and APK threat analysis.",
    version="1.0.0"
)


app.include_router(url_scan.router)
app.include_router(email_scan.router)
app.include_router(apk_scan.router)
app.include_router(auth.router)