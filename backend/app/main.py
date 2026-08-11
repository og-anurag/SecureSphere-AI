from fastapi import FastAPI
from app.routes import url_scan, email_scan, apk_scan

app = FastAPI()

app.include_router(url_scan.router)
app.include_router(email_scan.router)
app.include_router(apk_scan.router)