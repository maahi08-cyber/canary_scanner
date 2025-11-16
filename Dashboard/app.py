"""
Canary Dashboard - Phase 3: Web-Based Security Management Platform
==================================================================

A comprehensive web dashboard for managing secret detection findings,
providing real-time insights, historical trends, and actionable security intelligence.

Features:
- Real-time findings ingestion from CI/CD pipelines
- Interactive web dashboard with charts and metrics
- Slack integration for immediate alerting
- Finding status management (New/Acknowledged/Resolved)
- Historical trend analysis and reporting
- RESTful API for integration with other security tools

Technology Stack:
- FastAPI: Modern, fast web framework with automatic API documentation
- SQLAlchemy: Powerful ORM for database interactions
- PostgreSQL: Production-grade relational database
- Chart.js: Interactive charts and data visualization
- Jinja2: Template engine for server-side rendering

Author: Security Engineering Team
Version: 3.0.0
License: MIT
"""

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import logging
from contextlib import asynccontextmanager

# Local imports
from models.database import get_db, init_db
from models.scan import Scan
from models.finding import Finding
from utils.alerts import send_slack_alert, send_critical_alert
from utils.helpers import format_confidence_display, calculate_risk_score
from config import Settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
settings = Settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    logger.info("🚀 Starting Canary Dashboard...")
    init_db()
    logger.info("✅ Database initialized successfully")
    logger.info(f"🔗 Dashboard URL: http://localhost:8000")
    logger.info(f"📚 API Documentation: http://localhost:8000/docs")

    yield

    # Shutdown
    logger.info("🛑 Shutting down Canary Dashboard...")

# Initialize FastAPI app
app = FastAPI(
    title="Canary Security Dashboard",
    description="Web-based security management platform for secret detection findings",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
templates = Jinja2Templates(directory="dashboard/templates")

# ============================================================================
# API ENDPOINTS FOR CI/CD INTEGRATION
# ============================================================================

@app.post("/api/v1/scan", response_class=JSONResponse)
async def ingest_scan_results(
    scan_data: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Ingest scan results from CI/CD pipeline.

    Expected JSON payload:
    {
        "repository_name": "org/repo",
        "commit_hash": "abc123",
        "branch": "main",
        "scan_metadata": {
            "scanner_version": "2.0.0",
            "scan_timestamp": "2025-10-15T10:30:00Z",
            "total_findings": 3
        },
        "findings": [
            {
                "file_path": "src/config.py",
                "line_number": 15,
                "rule_id": "AWS-001",
                "description": "AWS Access Key ID",
                "confidence": "High",
                "secret_preview": "AKIA****"
            }
        ]
    }
    """
    try:
        # Validate required fields
        required_fields = ["repository_name", "commit_hash", "findings"]
        for field in required_fields:
            if field not in scan_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

        # Extract scan metadata
        scan_metadata = scan_data.get("scan_metadata", {})

        # Create new scan record
        scan = Scan(
            repository_name=scan_data["repository_name"],
            commit_hash=scan_data["commit_hash"],
            branch=scan_data.get("branch", "unknown"),
            scanner_version=scan_metadata.get("scanner_version", "unknown"),
            timestamp=datetime.utcnow(),
            findings_count=len(scan_data["findings"]),
            scan_duration=scan_metadata.get("scan_duration_seconds", 0)
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Process findings
        critical_findings = []
        findings_created = []

        for finding_data in scan_data["findings"]:
            finding = Finding(
                scan_id=scan.id,
                file_path=finding_data["file_path"],
                line_number=finding_data["line_number"],
                rule_id=finding_data["rule_id"],
                description=finding_data["description"],
                confidence=finding_data["confidence"],
                secret_preview=finding_data.get("secret_preview", "***"),
                status="New",  # Default status for new findings
                risk_score=calculate_risk_score(finding_data["confidence"]),
                created_at=datetime.utcnow()
            )

            db.add(finding)
            findings_created.append(finding)

            # Collect critical findings for alerting
            if finding_data["confidence"] == "High":
                critical_findings.append(finding)

        db.commit()

        # Schedule background alerts for critical findings
        if critical_findings:
            for finding in critical_findings:
                background_tasks.add_task(
                    send_critical_alert,
                    scan=scan,
                    finding=finding,
                    dashboard_url=f"{settings.dashboard_base_url}/scans/{scan.id}"
                )

        logger.info(f"✅ Processed scan for {scan.repository_name}: {len(findings_created)} findings, {len(critical_findings)} critical")

        return {
            "status": "success",
            "message": f"Scan processed successfully. Found {len(findings_created)} findings.",
            "scan_id": scan.id,
            "results_url": f"{settings.dashboard_base_url}/scans/{scan.id}",
            "critical_findings": len(critical_findings),
            "total_findings": len(findings_created)
        }

    except Exception as e:
        logger.error(f"❌ Error processing scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0.0"
    }

@app.get("/api/v1/metrics")
async def get_metrics(db: Session = Depends(get_db)):
    """Get dashboard metrics for API consumers."""
    try:
        # Calculate key metrics
        total_scans = db.query(Scan).count()
        total_findings = db.query(Finding).count()
        critical_findings = db.query(Finding).filter(Finding.confidence == "High").count()
        resolved_findings = db.query(Finding).filter(Finding.status == "Resolved").count()

        # Recent activity (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_scans = db.query(Scan).filter(Scan.timestamp >= week_ago).count()
        recent_findings = db.query(Finding).filter(Finding.created_at >= week_ago).count()

        # Top repositories by findings
        top_repos = db.query(
            Scan.repository_name,
            func.sum(Scan.findings_count).label('total_findings')
        ).group_by(Scan.repository_name).order_by(desc('total_findings')).limit(5).all()

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "resolved_findings": resolved_findings,
            "recent_activity": {
                "scans_last_7_days": recent_scans,
                "findings_last_7_days": recent_findings
            },
            "top_repositories": [
                {"name": repo.repository_name, "findings": repo.total_findings}
                for repo in top_repos
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch metrics")

# ============================================================================
# WEB DASHBOARD ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, db: Session = Depends(get_db)):
    """Main dashboard page with overview metrics and charts."""
    try:
        # Calculate overview metrics
        total_scans = db.query(Scan).count()
        total_findings = db.query(Finding).count()
        critical_findings = db.query(Finding).filter(Finding.confidence == "High").count()
        resolved_findings = db.query(Finding).filter(Finding.status == "Resolved").count()

        # Resolution rate calculation
        resolution_rate = (resolved_findings / total_findings * 100) if total_findings > 0 else 0

        # Recent scans (last 10)
        recent_scans = db.query(Scan).order_by(desc(Scan.timestamp)).limit(10).all()

        # Findings trend data for chart (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily_findings = db.query(
            func.date(Finding.created_at).label('date'),
            func.count(Finding.id).label('count')
        ).filter(
            Finding.created_at >= thirty_days_ago
        ).group_by(
            func.date(Finding.created_at)
        ).order_by('date').all()

        # Repository breakdown
        repo_stats = db.query(
            Scan.repository_name,
            func.sum(Scan.findings_count).label('total_findings'),
            func.count(Scan.id).label('scan_count')
        ).group_by(Scan.repository_name).order_by(desc('total_findings')).limit(8).all()

        # Confidence level distribution
        confidence_stats = db.query(
            Finding.confidence,
            func.count(Finding.id).label('count')
        ).group_by(Finding.confidence).all()

        # Prepare chart data
        chart_data = {
            "findings_trend": {
                "labels": [item.date.strftime('%m-%d') for item in daily_findings],
                "data": [item.count for item in daily_findings]
            },
            "repository_breakdown": {
                "labels": [repo.repository_name for repo in repo_stats],
                "data": [repo.total_findings for repo in repo_stats]
            },
            "confidence_distribution": {
                "labels": [item.confidence for item in confidence_stats],
                "data": [item.count for item in confidence_stats]
            }
        }

        return templates.TemplateResponse("index.html", {
            "request": request,
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "resolved_findings": resolved_findings,
            "resolution_rate": round(resolution_rate, 1),
            "recent_scans": recent_scans,
            "chart_data": json.dumps(chart_data),
            "page_title": "Security Dashboard"
        })

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load dashboard")

@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Detailed view of a specific scan with all findings."""
    try:
        # Get scan details
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get all findings for this scan
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(
            # Order by risk score (critical first), then by line number
            desc(Finding.risk_score),
            Finding.line_number
        ).all()

        # Categorize findings by confidence
        findings_by_confidence = {
            "High": [f for f in findings if f.confidence == "High"],
            "Medium": [f for f in findings if f.confidence == "Medium"],
            "Low": [f for f in findings if f.confidence == "Low"]
        }

        # Calculate status distribution
        status_counts = {}
        for finding in findings:
            status_counts[finding.status] = status_counts.get(finding.status, 0) + 1

        return templates.TemplateResponse("scan_detail.html", {
            "request": request,
            "scan": scan,
            "findings": findings,
            "findings_by_confidence": findings_by_confidence,
            "status_counts": status_counts,
            "page_title": f"Scan Details - {scan.repository_name}"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading scan details: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load scan details")

@app.get("/findings", response_class=HTMLResponse)
async def findings_management(
    request: Request, 
    status: Optional[str] = None,
    confidence: Optional[str] = None,
    repository: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Findings management page with filtering and status updates."""
    try:
        # Build query with filters
        query = db.query(Finding).join(Scan)

        if status:
            query = query.filter(Finding.status == status)
        if confidence:
            query = query.filter(Finding.confidence == confidence)
        if repository:
            query = query.filter(Scan.repository_name == repository)

        # Get filtered findings
        findings = query.order_by(desc(Finding.created_at)).limit(100).all()

        # Get filter options
        all_repositories = db.query(Scan.repository_name).distinct().all()
        repositories = [repo[0] for repo in all_repositories]

        status_options = ["New", "Acknowledged", "Resolved", "False Positive"]
        confidence_options = ["High", "Medium", "Low"]

        return templates.TemplateResponse("findings.html", {
            "request": request,
            "findings": findings,
            "repositories": repositories,
            "status_options": status_options,
            "confidence_options": confidence_options,
            "current_filters": {
                "status": status,
                "confidence": confidence,
                "repository": repository
            },
            "page_title": "Findings Management"
        })

    except Exception as e:
        logger.error(f"Error loading findings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load findings")

@app.post("/api/v1/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int,
    status_data: dict,
    db: Session = Depends(get_db)
):
    """Update the status of a specific finding."""
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        new_status = status_data.get("status")
        if new_status not in ["New", "Acknowledged", "Resolved", "False Positive"]:
            raise HTTPException(status_code=400, detail="Invalid status")

        # Update finding
        old_status = finding.status
        finding.status = new_status
        finding.updated_at = datetime.utcnow()

        # Add notes if provided
        if "notes" in status_data:
            finding.notes = status_data["notes"]

        db.commit()

        logger.info(f"✅ Finding {finding_id} status updated: {old_status} → {new_status}")

        return {
            "status": "success",
            "message": f"Finding status updated to {new_status}",
            "finding_id": finding_id,
            "old_status": old_status,
            "new_status": new_status
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating finding status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update finding status")

# ============================================================================
# ADVANCED FEATURES
# ============================================================================

@app.get("/api/v1/trends")
async def get_security_trends(
    days: int = 30,
    db: Session = Depends(get_db)
):
    """Get security trends over time for dashboard charts."""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Daily finding counts
        daily_trends = db.query(
            func.date(Finding.created_at).label('date'),
            func.count(Finding.id).label('total'),
            func.sum(func.case([(Finding.confidence == 'High', 1)], else_=0)).label('critical')
        ).filter(
            Finding.created_at >= cutoff_date
        ).group_by(
            func.date(Finding.created_at)
        ).order_by('date').all()

        # Repository risk scores
        repo_risks = db.query(
            Scan.repository_name,
            func.avg(Finding.risk_score).label('avg_risk'),
            func.count(Finding.id).label('finding_count')
        ).join(Finding).group_by(
            Scan.repository_name
        ).having(func.count(Finding.id) >= 3).all()  # Only repos with 3+ findings

        return {
            "daily_trends": [
                {
                    "date": trend.date.isoformat(),
                    "total_findings": trend.total,
                    "critical_findings": trend.critical
                }
                for trend in daily_trends
            ],
            "repository_risk_scores": [
                {
                    "repository": repo.repository_name,
                    "average_risk_score": float(repo.avg_risk),
                    "finding_count": repo.finding_count
                }
                for repo in repo_risks
            ]
        }

    except Exception as e:
        logger.error(f"Error fetching trends: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch trends")

@app.post("/api/v1/test-alert")
async def test_slack_alert(background_tasks: BackgroundTasks):
    """Test endpoint for Slack integration."""
    try:
        # Create a test alert
        background_tasks.add_task(
            send_slack_alert,
            message="🧪 Test Alert: Canary Dashboard is connected and working!",
            channel="#security-alerts"
        )

        return {
            "status": "success",
            "message": "Test alert sent to Slack"
        }

    except Exception as e:
        logger.error(f"Error sending test alert: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send test alert")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
