from fastapi import FastAPI
from app.routes.home import router as home_router
from app.routes.url_scan import router as url_scan_router

app = FastAPI()

app.include_router(home_router)
app.include_router(url_scan_router)