import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from auth.routes import router as auth_router
from users.routes import router as users_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PAGE = os.path.join(BASE_DIR, "index.html")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router, prefix="/users", tags=["users"])

@app.get("/")
def read_root():
    """Serves index.html (same origin as the API) if it is next to this file."""
    if os.path.exists(HTML_PAGE):
        return FileResponse(HTML_PAGE)
    return {"message": "Welcome to FastAPI authentication and authorization example"}

if __name__ == "__main__":
    import uvicorn

    # No Gmail configured -> DEV MODE: the OTP is printed in this terminal instead of e-mailed
    if not (os.getenv("GMAIL_ADDRESS") and os.getenv("GMAIL_APP_PASSWORD")):
        os.environ["AUTH_DEV_MODE"] = "true"
        print("[test] Gmail not configured -> DEV MODE: OTP codes are printed here.")

    print("[test] Open http://localhost:8000")
    uvicorn.run("main:app", reload=True)