from fastapi import FastAPI
from securecloud_main import SecureCloudAIGuardian

app = FastAPI()

guardian = SecureCloudAIGuardian()

@app.get("/")
def status():
    return {"status": "SecureCloud AI Guardian Active"}

@app.get("/dashboard")
def dashboard():
    return guardian.get_dashboard_data()
