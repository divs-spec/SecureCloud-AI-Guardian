from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from securecloud_main import SecureCloudAIGuardian

app = FastAPI()
guardian = SecureCloudAIGuardian()

@app.get("/")
def home():
    return {"status": "SecureCloud AI Guardian Running"}

@app.get("/dashboard")
def dashboard():
    return guardian.get_dashboard_data()

@app.get("/dashboard-ui")
def ui():
    with open("securecloud_dashboard.html", "r") as f:
        return HTMLResponse(f.read())
