# api/index.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from securecloud_main import SecureCloudAIGuardian
from starlette.requests import Request
from starlette.responses import Response

app = FastAPI(title="SecureCloud AI Guardian API (instrumented)")

# Create guardian instance (do NOT start infinite loops on import)
guardian = SecureCloudAIGuardian()

# Instrumentator: automatically creates metrics for requests, latency, paths, etc.
Instrumentator().instrument(app).expose(app, include_in_schema=False, should_gzip=True)

@app.get("/", tags=["status"])
def home():
    return {"status": "SecureCloud AI Guardian Running"}

@app.get("/api/health", tags=["status"])
def health():
    return {"status": "healthy"}

@app.get("/dashboard", tags=["data"])
def dashboard():
    # synchronous summary endpoint; keep response sizes small for metrics consumption
    return guardian.get_dashboard_data()

@app.get("/dashboard-ui", tags=["ui"])
def dashboard_ui():
    with open("securecloud_dashboard.html", "r") as f:
        return HTMLResponse(f.read())

# Optional: a metrics endpoint if you prefer manual control (Instrumentator's expose() already adds it)
@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    # If you want to limit or do auth for /metrics, do it here.
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
