from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def home():
    return {
        "message": "Welcome to SecureSphere AI Backend!"
    }


@router.get("/about")
def about():
    return {
        "project": "SecureSphere AI",
        "developer": "Backend Team"
    }


@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "securesphere-ai-api"
    }