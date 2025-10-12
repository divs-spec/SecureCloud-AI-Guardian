#!/usr/bin/env python3
"""
SecureCloud AI Guardian - FastAPI Backend
REST API for the security dashboard and monitoring system
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import asyncio
import json
import os
from datetime import datetime, timedelta
import logging
from contextlib import asynccontextmanager

# Import our main guardian class
import sys
sys.path.append(os.path.dirname(__file__))

# Pydantic models for API
class SecurityEventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    target_resource: str
    description: str
    provider: str
    ai_confidence: float
    is_anomaly: bool

class CloudResourceResponse(BaseModel):
    id: str
    name: str
    type: str
    provider: str
    region: str
    risk_score: float
    tags: Dict[str, str]
    last_accessed: datetime

class ThreatResponse(BaseModel):
    pattern_id: str
    pattern_type: str
    confidence: float
    event_count: int
    description: str

class DashboardResponse(BaseModel):
    total_resources: int
    active_threats: int
    recent_events: int
    high_risk_resources: int
    cloud_coverage: List[str]
    ai_model_health: Dict[str, str]
    threat_trends: Dict[str, int]
    last_updated: datetime

class AIModelHealthResponse(BaseModel):
    model_id: str
    model_name: str
    accuracy: float
    drift_score: float
    last_training: datetime
    prediction_confidence: float
    adversarial_attempts: int
    status: str

class IncidentResponse(BaseModel):
    incident_id: str
    event_id: str
    severity: str
    status: str
    actions_taken: List[str]
    created_at: datetime
    resolved_at: Optional[datetime]

# Global guardian instance
guardian_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    global guardian_instance
    
    # Startup
    logging.info("Starting SecureCloud AI Guardian API...")
    
    # Import and initialize the guardian
    try:
        from securecloud_main import SecureCloudAIGuardian
        guardian_instance = SecureCloudAIGuardian()
        
        # Start monitoring in background
        monitoring_task = asyncio.create_task(guardian_instance.start_monitoring())
        
        logging.info("Guardian monitoring started successfully")
        yield
        
    except Exception as e:
        logging.error(f"Failed to start guardian: {e}")
        raise
    
    # Shutdown
    logging.info("Shutting down SecureCloud AI Guardian API...")
    if monitoring_task:
        monitoring_task.cancel()
        try:
            await monitoring_task
        except asyncio.CancelledError:
            pass

# Initialize FastAPI app
app = FastAPI(
    title="SecureCloud AI Guardian API",
    description="AI-powered multi-cloud security orchestration platform",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_embedded_dashboard_html() -> str:
    """Return the embedded dashboard HTML"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureCloud AI Guardian - Security Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
            color: #ffffff;
            overflow-x: hidden;
        }

        .header {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #ff00ff);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff88;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .metric-card:hover {
            transform: translateY(-5px);
            border-color: rgba(0, 212, 255, 0.3);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.2);
        }

        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #00d4ff, #ffffff);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .metric-label {
            font-size: 0.9rem;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .chart-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem;
        }

        .chart-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #ffffff;
        }

        .events-section {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
        }

        .events-container, .threats-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem;
        }

        .event-item {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }

        .event-item:hover {
            background: rgba(255, 255, 255, 0.12);
            transform: translateX(5px);
        }

        .event-severity {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-critical { background: #ff4757; }
        .severity-high { background: #ff6b47; }
        .severity-medium { background: #ffa502; }
        .severity-low { background: #26de81; }

        .threat-item {
            background: rgba(255, 68, 87, 0.1);
            border: 1px solid rgba(255, 68, 87, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            position: relative;
        }

        .threat-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background: #ff4757;
            border-radius: 0 4px 4px 0;
        }

        .ai-status {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }

        .ai-model-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid rgba(0, 212, 255, 0.2);
            border-radius: 12px;
            padding: 1rem;
            text-align: center;
        }

        .ai-model-name {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .ai-model-status {
            font-size: 0.9rem;
            opacity: 0.8;
        }

        .refresh-btn {
            background: linear-gradient(135deg, #00d4ff, #ff00ff);
            border: none;
            color: white;
            padding: 0.8rem 1.5rem;
            border-radius: 25px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .refresh-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 15px rgba(0, 212, 255, 0.4);
        }

        .cloud-coverage {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }

        .cloud-provider {
            background: rgba(255, 255, 255, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .provider-aws { border-left: 4px solid #ff9500; }
        .provider-azure { border-left: 4px solid #0078d4; }
        .provider-gcp { border-left: 4px solid #4285f4; }

        @media (max-width: 768px) {
            .charts-grid, .events-section {
                grid-template-columns: 1fr;
            }
            
            .dashboard {
                padding: 1rem;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">🛡️ SecureCloud AI Guardian</div>
        <div class="status-indicator">
            <div class="status-dot"></div>
            <span>System Active</span>
        </div>
        <button class="refresh-btn" onclick="refreshDashboard()">🔄 Refresh</button>
    </header>

    <main class="dashboard">
        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value" id="totalResources">247</div>
                <div class="metric-label">Total Resources</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="activeThreats">3</div>
                <div class="metric-label">Active Threats</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="recentEvents">12</div>
                <div class="metric-label">Events (24h)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="highRiskResources">8</div>
                <div class="metric-label">High Risk Resources</div>
            </div>
        </section>

        <section class="charts-grid">
            <div class="chart-container">
                <h3 class="chart-title">📊 Threat Timeline (24h)</h3>
                <canvas id="threatTimelineChart" width="400" height="200"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">🎯 Threat Distribution</h3>
                <canvas id="threatDistributionChart" width="300" height="300"></canvas>
            </div>
        </section>

        <section class="events-section">
            <div class="events-container">
                <h3 class="chart-title">🚨 Recent Security Events</h3>
                <div id="eventsList"></div>
            </div>
            <div class="threats-container">
                <h3 class="chart-title">⚠️ Active Threats</h3>
                <div id="threatsList"></div>
            </div>
        </section>

        <section class="chart-container">
            <h3 class="chart-title">☁️ Multi-Cloud Coverage</h3>
            <div class="cloud-coverage">
                <div class="cloud-provider provider-aws">
                    <span>🟧</span> AWS (127 resources)
                </div>
                <div class="cloud-provider provider-azure">
                    <span>🔵</span> Azure (89 resources)
                </div>
                <div class="cloud-provider provider-gcp">
                    <span>🔴</span> GCP (31 resources)
                </div>
            </div>
        </section>

        <section class="ai-status">
            <h3 class="chart-title" style="grid-column: 1 / -1;">🤖 AI Model Health</h3>
            <div class="ai-model-card">
                <div class="ai-model-name">Network Anomaly</div>
                <div class="ai-model-status">✅ Healthy (98.2% accuracy)</div>
            </div>
            <div class="ai-model-card">
                <div class="ai-model-name">User Behavior</div>
                <div class="ai-model-status">✅ Healthy (96.7% accuracy)</div>
            </div>
            <div class="ai-model-card">
                <div class="ai-model-name">Malware Detection</div>
                <div class="ai-model-status">⚠️ Model Drift (0.31)</div>
            </div>
            <div class="ai-model-card">
                <div class="ai-model-name">Config Drift</div>
                <div class="ai-model-status">✅ Healthy (94.1% accuracy)</div>
            </div>
        </section>
    </main>

    <script>
        let dashboardData = {
            totalResources: 247,
            activeThreats: 3,
            recentEvents: 12,
            highRiskResources: 8,
            events: [
                {
                    type: "LOGIN_ATTEMPT",
                    severity: "HIGH",
                    description: "Multiple failed login attempts from suspicious IP",
                    timestamp: "2 minutes ago",
                    source: "192.168.1.142"
                },
                {
                    type: "CONFIG_CHANGE",
                    severity: "MEDIUM",
                    description: "Security group configuration modified",
                    timestamp: "5 minutes ago",
                    source: "admin@company.com"
                },
                {
                    type: "DATA_ACCESS",
                    severity: "CRITICAL",
                    description: "Unauthorized access to sensitive database",
                    timestamp: "8 minutes ago",
                    source: "10.0.1.55"
                },
                {
                    type: "NETWORK_ACCESS",
                    severity: "LOW",
                    description: "New device connected to network",
                    timestamp: "12 minutes ago",
                    source: "192.168.1.201"
                }
            ],
            threats: [
                {
                    name: "Brute Force Attack Campaign",
                    confidence: 0.94,
                    description: "Coordinated login attempts from multiple IPs",
                    affected_resources: 12
                },
                {
                    name: "Data Exfiltration Pattern",
                    confidence: 0.87,
                    description: "Unusual data access patterns detected",
                    affected_resources: 3
                }
            ]
        };

        function initializeDashboard() {
            updateMetrics();
            createThreatTimelineChart();
            createThreatDistributionChart();
            renderEvents();
            renderThreats();
        }

        function updateMetrics() {
            document.getElementById('totalResources').textContent = dashboardData.totalResources;
            document.getElementById('activeThreats').textContent = dashboardData.activeThreats;
            document.getElementById('recentEvents').textContent = dashboardData.recentEvents;
            document.getElementById('highRiskResources').textContent = dashboardData.highRiskResources;
        }

        function createThreatTimelineChart() {
            const ctx = document.getElementById('threatTimelineChart').getContext('2d');
            const hours = Array.from({length: 24}, (_, i) => `${23-i}h`).reverse();
            const threatCounts = [2, 3, 1, 4, 2, 5, 3, 6, 4, 7, 5, 8, 6, 9, 7, 5, 4, 6, 5, 7, 6, 4, 3, 2];
            
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: hours,
                    datasets: [{
                        label: 'Security Events',
                        data: threatCounts,
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#ffffff' }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#ffffff', maxTicksLimit: 6 },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        },
                        y: {
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        }
                    }
                }
            });
        }

        function createThreatDistributionChart() {
            const ctx = document.getElementById('threatDistributionChart').getContext('2d');
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Login Attempts', 'Config Changes', 'Data Access', 'Network Events', 'Model Issues'],
                    datasets: [{
                        data: [35, 20, 15, 20, 10],
                        backgroundColor: ['#ff4757', '#ff6b47', '#ffa502', '#26de81', '#00d4ff'],
                        borderWidth: 2,
                        borderColor: '#1a1a3e'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#ffffff', padding: 15, usePointStyle: true }
                        }
                    }
                }
            });
        }

        function renderEvents() {
            const eventsList = document.getElementById('eventsList');
            eventsList.innerHTML = '';
            
            dashboardData.events.forEach(event => {
                const eventItem = document.createElement('div');
                eventItem.className = 'event-item';
                eventItem.innerHTML = `
                    <div>
                        <div style="font-weight: 600; margin-bottom: 0.3rem;">${event.description}</div>
                        <div style="font-size: 0.9rem; opacity: 0.7;">
                            ${event.type} • ${event.source} • ${event.timestamp}
                        </div>
                    </div>
                    <div class="event-severity severity-${event.severity.toLowerCase()}">${event.severity}</div>
                `;
                eventsList.appendChild(eventItem);
            });
        }

        function renderThreats() {
            const threatsList = document.getElementById('threatsList');
            threatsList.innerHTML = '';
            
            dashboardData.threats.forEach(threat => {
                const threatItem = document.createElement('div');
                threatItem.className = 'threat-item';
                threatItem.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">${threat.name}</div>
                    <div style="font-size: 0.9rem; margin-bottom: 0.5rem;">${threat.description}</div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; opacity: 0.8;">
                        <span>Confidence: ${(threat.confidence * 100).toFixed(1)}%</span>
                        <span>${threat.affected_resources} resources affected</span>
                    </div>
                `;
                threatsList.appendChild(threatItem);
            });
        }

        function refreshDashboard() {
            dashboardData.recentEvents = Math.floor(Math.random() * 20) + 5;
            dashboardData.activeThreats = Math.floor(Math.random() * 8) + 1;
            updateMetrics();
            
            const btn = event.target;
            btn.style.transform = 'rotate(360deg)';
            setTimeout(() => btn.style.transform = 'rotate(0deg)', 500);
        }

        setInterval(refreshDashboard, 30000);
        document.addEventListener('DOMContentLoaded', initializeDashboard);
    </script>
</body>
</html>"""

# Dependency to get guardian instance
def get_guardian():
    if guardian_instance is None:
        raise HTTPException(status_code=503, detail="Guardian service not available")
    return guardian_instance

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Redirect to dashboard"""
    return HTMLResponse(content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureCloud AI Guardian</title>
            <meta http-equiv="refresh" content="0;url=/dashboard">
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
                    color: #ffffff;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    text-align: center;
                }
                h1 {
                    font-size: 2rem;
                    margin-bottom: 1rem;
                    background: linear-gradient(135deg, #00d4ff, #ff00ff);
                    background-clip: text;
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ SecureCloud AI Guardian</h1>
                <p>Redirecting to dashboard...</p>
            </div>
            <script>window.location.href="/dashboard";</script>
        </body>
        </html>
    """)

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    """Get the security dashboard"""
    # Serve the actual dashboard HTML
    dashboard_html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    
    # If file exists, serve it
    if os.path.exists(dashboard_html_path):
        with open(dashboard_html_path, 'r') as f:
            return HTMLResponse(content=f.read())
    
    # Otherwise, return the embedded dashboard
    return HTMLResponse(content=get_embedded_dashboard_html())

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(), "service": "SecureCloud AI Guardian"}

@app.get("/api/dashboard", response_model=DashboardResponse)
async def get_dashboard_data(guardian = Depends(get_guardian)):
    """Get dashboard overview data"""
    try:
        data = guardian.get_dashboard_data()
        return DashboardResponse(
            total_resources=data["total_resources"],
            active_threats=data["active_threats"],
            recent_events=data["recent_events"],
            high_risk_resources=data["high_risk_resources"],
            cloud_coverage=[provider.value for provider in data["cloud_coverage"]],
            ai_model_health=data["ai_model_health"],
            threat_trends=data["threat_trends"],
            last_updated=datetime.now()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

@app.get("/api/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    limit: int = 50,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    guardian = Depends(get_guardian)
):
    """Get recent security events"""
    try:
        events = list(guardian.security_events)
        
        # Apply filters
        if severity:
            events = [e for e in events if e.severity.lower() == severity.lower()]
        
        if event_type:
            events = [e for e in events if e.event_type.lower() == event_type.lower()]
        
        # Sort by timestamp (newest first) and limit
        events = sorted(events, key=lambda x: x.timestamp, reverse=True)[:limit]
        
        return [
            SecurityEventResponse(
                id=event.id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                severity=event.severity,
                source_ip=event.source_ip,
                target_resource=event.target_resource,
                description=event.description,
                provider=event.provider.value,
                ai_confidence=event.ai_confidence,
                is_anomaly=event.is_anomaly
            ) for event in events
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get security events: {str(e)}")

@app.get("/api/threats", response_model=List[ThreatResponse])
async def get_active_threats(guardian = Depends(get_guardian)):
    """Get active threat intelligence"""
    try:
        threats = []
        for threat_id, threat_data in guardian.active_threats.items():
            threats.append(ThreatResponse(
                pattern_id=threat_id,
                pattern_type=threat_data["pattern_type"],
                confidence=threat_data["confidence"],
                event_count=threat_data["event_count"],
                description=threat_data["description"]
            ))
        
        return threats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threats: {str(e)}")

@app.get("/api/resources", response_model=List[CloudResourceResponse])
async def get_cloud_resources(
    provider: Optional[str] = None,
    high_risk_only: bool = False,
    guardian = Depends(get_guardian)
):
    """Get cloud resources"""
    try:
        all_resources = []
        
        for cloud_provider, resources in guardian.resources_cache.items():
            if provider and cloud_provider.value.lower() != provider.lower():
                continue
                
            for resource in resources:
                if high_risk_only and resource.risk_score <= 0.7:
                    continue
                    
                all_resources.append(CloudResourceResponse(
                    id=resource.id,
                    name=resource.name,
                    type=resource.type,
                    provider=resource.provider.value,
                    region=resource.region,
                    risk_score=resource.risk_score,
                    tags=resource.tags,
                    last_accessed=resource.last_accessed
                ))
        
        return all_resources
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get resources: {str(e)}")

@app.get("/api/ai-models", response_model=List[AIModelHealthResponse])
async def get_ai_model_health(guardian = Depends(get_guardian)):
    """Get AI model health status"""
    try:
        models_health = []
        
        for model_name, model in guardian.ai_models.items():
            metrics = await guardian.model_safety_monitor.check_model_health(model)
            
            # Determine status based on metrics
            status = "healthy"
            if metrics.drift_score > 0.3:
                status = "drift_detected"
            elif metrics.accuracy < 0.9:
                status = "performance_degraded"
            elif metrics.adversarial_attempts > 10:
                status = "under_attack"
            
            models_health.append(AIModelHealthResponse(
                model_id=metrics.model_id,
                model_name=model_name,
                accuracy=metrics.accuracy,
                drift_score=metrics.drift_score,
                last_training=metrics.last_training,
                prediction_confidence=metrics.prediction_confidence,
                adversarial_attempts=metrics.adversarial_attempts,
                status=status
            ))
        
        return models_health
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get AI model health: {str(e)}")

@app.get("/api/incidents", response_model=List[IncidentResponse])
async def get_incidents(
    status: Optional[str] = None,
    limit: int = 20,
    guardian = Depends(get_guardian)
):
    """Get security incidents and responses"""
    try:
        incidents = []
        
        for response_id, response_data in guardian.response_orchestrator.active_responses.items():
            if status and response_data["status"].lower() != status.lower():
                continue
                
            incidents.append(IncidentResponse(
                incident_id=response_id,
                event_id=response_data["event_id"],
                severity="HIGH",  # Default severity
                status=response_data["status"],
                actions_taken=response_data["actions"],
                created_at=response_data["timestamp"],
                resolved_at=response_data["timestamp"] if response_data["status"] == "completed" else None
            ))
        
        return incidents[:limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get incidents: {str(e)}")

@app.post("/api/events/{event_id}/respond")
async def trigger_incident_response(
    event_id: str,
    background_tasks: BackgroundTasks,
    guardian = Depends(get_guardian)
):
    """Trigger manual incident response for an event"""
    try:
        # Find the event
        event = None
        for e in guardian.security_events:
            if e.id == event_id:
                event = e
                break
        
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        
        # Trigger response in background
        background_tasks.add_task(guardian.response_orchestrator.handle_incident, event)
        
        return {"message": "Incident response triggered", "event_id": event_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger response: {str(e)}")

@app.post("/api/ai-models/{model_name}/retrain")
async def retrain_ai_model(
    model_name: str,
    background_tasks: BackgroundTasks,
    guardian = Depends(get_guardian)
):
    """Trigger AI model retraining"""
    try:
        if model_name not in guardian.ai_models:
            raise HTTPException(status_code=404, detail="AI model not found")
        
        # In real implementation, trigger actual retraining
        background_tasks.add_task(_simulate_model_retraining, model_name)
        
        return {"message": f"Retraining triggered for {model_name}", "model": model_name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger retraining: {str(e)}")

async def _simulate_model_retraining(model_name: str):
    """Simulate model retraining process"""
    await asyncio.sleep(5)  # Simulate training time
    logging.info(f"Model {model_name} retraining completed (simulated)")

@app.get("/api/analytics/threat-timeline")
async def get_threat_timeline(
    hours: int = 24,
    guardian = Depends(get_guardian)
):
    """Get threat timeline analytics"""
    try:
        # Get events from the specified time window
        start_time = datetime.now() - timedelta(hours=hours)
        events = [e for e in guardian.security_events if e.timestamp >= start_time]
        
        # Group by hour
        timeline = {}
        for event in events:
            hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            if hour_key not in timeline:
                timeline[hour_key] = {"total": 0, "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}}
            
            timeline[hour_key]["total"] += 1
            timeline[hour_key]["by_severity"][event.severity] += 1
        
        return {"timeline": timeline, "total_events": len(events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat timeline: {str(e)}")

@app.get("/api/analytics/risk-assessment")
async def get_risk_assessment(guardian = Depends(get_guardian)):
    """Get overall security risk assessment"""
    try:
        all_resources = []
        for resources in guardian.resources_cache.values():
            all_resources.extend(resources)
        
        if not all_resources:
            return {"overall_risk": "unknown", "risk_distribution": {}}
        
        # Calculate risk distribution
        risk_ranges = {
            "low": len([r for r in all_resources if r.risk_score <= 0.3]),
            "medium": len([r for r in all_resources if 0.3 < r.risk_score <= 0.7]),
            "high": len([r for r in all_resources if r.risk_score > 0.7])
        }
        
        # Calculate overall risk
        avg_risk = sum(r.risk_score for r in all_resources) / len(all_resources)
        
        if avg_risk <= 0.3:
            overall_risk = "low"
        elif avg_risk <= 0.6:
            overall_risk = "medium"
        else:
            overall_risk = "high"
        
        return {
            "overall_risk": overall_risk,
            "average_risk_score": avg_risk,
            "risk_distribution": risk_ranges,
            "total_resources": len(all_resources),
            "recommendations": _generate_risk_recommendations(risk_ranges, overall_risk)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get risk assessment: {str(e)}")

def _generate_risk_recommendations(risk_ranges: Dict[str, int], overall_risk: str) -> List[str]:
    """Generate security recommendations based on risk assessment"""
    recommendations = []
    
    if risk_ranges["high"] > 0:
        recommendations.append(f"Immediately review {risk_ranges['high']} high-risk resources")
    
    if overall_risk == "high":
        recommendations.append("Consider implementing additional security controls")
        recommendations.append("Schedule comprehensive security audit")
    
    if risk_ranges["medium"] > risk_ranges["low"]:
        recommendations.append("Focus on reducing medium-risk resources through configuration improvements")
    
    recommendations.append("Maintain regular security monitoring and updates")
    
    return recommendations

@app.get("/api/config/clouds")
async def get_cloud_configuration():
    """Get cloud provider configuration status"""
    return {
        "providers": [
            {
                "name": "AWS",
                "status": "connected",
                "regions": ["us-east-1", "us-west-2", "eu-west-1"],
                "services_monitored": ["EC2", "S3", "RDS", "IAM"]
            },
            {
                "name": "Azure",
                "status": "connected",
                "regions": ["eastus", "westus2", "westeurope"],
                "services_monitored": ["VirtualMachines", "Storage", "KeyVault"]
            },
            {
                "name": "GCP",
                "status": "connected",
                "regions": ["us-central1", "us-west1", "europe-west1"],
                "services_monitored": ["ComputeEngine", "CloudStorage", "CloudSQL"]
            }
        ]
    }

@app.websocket("/ws/events")
async def websocket_events(websocket):
    """WebSocket endpoint for real-time security events"""
    await websocket.accept()
    
    try:
        guardian = get_guardian()
        last_event_count = len(guardian.security_events)
        
        while True:
            # Check for new events
            current_event_count = len(guardian.security_events)
            
            if current_event_count > last_event_count:
                # Send new events
                new_events = list(guardian.security_events)[last_event_count:]
                for event in new_events:
                    event_data = {
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "severity": event.severity,
                        "description": event.description,
                        "provider": event.provider.value
                    }
                    await websocket.send_json(event_data)
                
                last_event_count = current_event_count
            
            await asyncio.sleep(1)  # Check every second
            
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Endpoint not found", "path": str(request.url)}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

# Additional utility endpoints
@app.get("/api/stats")
async def get_system_stats(guardian = Depends(get_guardian)):
    """Get system statistics"""
    try:
        uptime_start = datetime.now() - timedelta(hours=24)  # Simulated uptime
        
        return {
            "uptime": "24h 15m",
            "events_processed": len(guardian.security_events),
            "threats_detected": len(guardian.active_threats),
            "ai_predictions": sum(1 for _ in guardian.security_events if hasattr(_, 'ai_confidence')),
            "automated_responses": len(guardian.response_orchestrator.active_responses),
            "system_health": "optimal",
            "memory_usage": "342 MB",
            "cpu_usage": "12%"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get system stats: {str(e)}")

@app.post("/api/simulate-attack")
async def simulate_security_attack(
    attack_type: str = "brute_force",
    intensity: str = "medium",
    guardian = Depends(get_guardian)
):
    """Simulate a security attack for testing (demo purposes only)"""
    try:
        # Create simulated attack events
        attack_events = []
        
        if attack_type == "brute_force":
            for i in range(5 if intensity == "medium" else 10):
                await guardian._create_security_event(
                    "LOGIN_ATTEMPT",
                    f"Simulated brute force attempt #{i+1}",
                    guardian.cloud_connectors[list(guardian.cloud_connectors.keys())[0]].provider if guardian.cloud_connectors else None,
                    {"simulated": True, "attack_type": attack_type}
                )
        
        elif attack_type == "data_breach":
            await guardian._create_security_event(
                "DATA_ACCESS",
                "Simulated unauthorized data access",
                guardian.cloud_connectors[list(guardian.cloud_connectors.keys())[0]].provider if guardian.cloud_connectors else None,
                {"simulated": True, "attack_type": attack_type, "severity": "CRITICAL"}
            )
        
        return {
            "message": f"Simulated {attack_type} attack with {intensity} intensity",
            "events_created": len(attack_events) if attack_events else 1
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to simulate attack: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the API server
    uvicorn.run(
        "securecloud_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Enable auto-reload for development
        log_level="info"
    )
