"""
FastAPI Main Application
========================
Provides REST API endpoints for the vulnerability assessment tool.

Endpoints:
    POST /scans          — Submit a URL for scanning, returns scan_id immediately
    GET  /scans/{id}     — Get scan status and results
    GET  /scans          — List all scans
    DELETE /scans/{id}   — Delete a scan

Install dependencies:
    pip install fastapi uvicorn celery redis sqlalchemy psycopg2-binary python-dotenv requests

Run:
    uvicorn api.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from reports.pdf_generator import PDFGenerator
from reports.excel_generator import ExcelGenerator
from datetime import datetime, date 
from typing import Optional
import uuid
import json
import os
from sqlalchemy import text
from db.database import get_db
from db.models import Admin
from db.scan_store import SessionLocal
from middleware.logging_middleware import RequestLoggingMiddleware
from handlers.exception_handler import global_exception_handler
from api.models import (
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    ScanListResponse,
    ScanStatus,
)
from api.tasks import run_scan_task
from db.scan_store import scan_store
import logging

from services import audit_logger
from services.audit_logger import audit_logger
logger = logging.getLogger(__name__)
# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

app = FastAPI(
    title="AI-Powered Vulnerability Assessment Tool",
    description="Submit a URL and get a full vulnerability report powered by OWASP ZAP and AI analysis.",
    version="0.1.0",
)

from db.database import init_db
app.add_middleware(RequestLoggingMiddleware)
app.add_exception_handler(Exception, global_exception_handler)

@app.on_event("startup")
def startup_event():
    init_db()

# Allow frontend (React/Next.js) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def check_and_increment_scan_limit(user_id: str, email: str, daily_limit: int = 3) -> tuple[bool, int]:
    """
    Check if user has scans remaining today.
    Returns (allowed: bool, scans_used: int)
    """
    from db.database import SessionLocal
    db = SessionLocal()
    try:
        today = date.today()
        
        # Get or create today's record
        result = db.execute(text("""
            INSERT INTO user_scan_limits (user_id, email, scan_date, scan_count, daily_limit)
            VALUES (:user_id, :email, :today, 0, :limit)
            ON CONFLICT (user_id, scan_date) DO NOTHING
            RETURNING scan_count
        """), {"user_id": user_id, "email": email, "today": today, "limit": daily_limit})
        db.commit()

        # Get current count
        row = db.execute(text("""
            SELECT scan_count, daily_limit 
            FROM user_scan_limits 
            WHERE user_id = :user_id AND scan_date = :today
        """), {"user_id": user_id, "today": today}).fetchone()

        if not row:
            return False, 0

        scan_count = row[0]
        limit = row[1]

        if scan_count >= limit:
            return False, scan_count

        # Increment count
        db.execute(text("""
            UPDATE user_scan_limits 
            SET scan_count = scan_count + 1
            WHERE user_id = :user_id AND scan_date = :today
        """), {"user_id": user_id, "today": today})
        db.commit()

        return True, scan_count + 1

    except Exception as e:
        db.rollback()
        logger.error(f"Limit check failed: {e}")
        return True, 0  # fail open — don't block scan if DB has issues
    finally:
        db.close()
# ──────────────────────────────────────────────
# Admin helpers
# ──────────────────────────────────────────────

def require_admin(user_id: str):
    """Raise 403 if user is not an admin."""
    if not scan_store.is_admin(user_id):
        raise HTTPException(status_code=403, detail="Admin access required")


# ──────────────────────────────────────────────
# Admin routes — Phase 1
# ──────────────────────────────────────────────

@app.get("/admin/check", tags=["Admin"])
def check_admin(user_id: str):
    """Check if a user has admin role."""

    is_admin = scan_store.is_admin(user_id)

    if is_admin:
        audit_logger.log_event(
            event_type="ADMIN_LOGIN",
            performed_by=user_id,
            entity_type="admin",
            action="Admin panel accessed",
        )

    return {"is_admin": is_admin}

@app.get("/admin/stats", tags=["Admin"])
def get_admin_stats(user_id: str):
    """Get platform-wide statistics. Admin only."""
    require_admin(user_id)

    db = SessionLocal()
    try:
        today = date.today().isoformat()

        total_scans = db.execute(
            text("SELECT COUNT(*) FROM scans")
        ).scalar()

        today_scans = db.execute(
            text("SELECT COUNT(*) FROM scans WHERE DATE(created_at) = :today"),
            {"today": today}
        ).scalar()

        completed = db.execute(
            text("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        ).scalar()

        running = db.execute(
            text("SELECT COUNT(*) FROM scans WHERE status = 'running'")
        ).scalar()

        failed = db.execute(
            text("SELECT COUNT(*) FROM scans WHERE status = 'failed'")
        ).scalar()

        total_users = db.execute(
            text("SELECT COUNT(DISTINCT user_id) FROM scans WHERE user_id IS NOT NULL")
        ).scalar()

        return {
            "total_scans":     int(total_scans or 0),
            "today_scans":     int(today_scans or 0),
            "completed_scans": int(completed or 0),
            "running_scans":   int(running or 0),
            "failed_scans":    int(failed or 0),
            "total_users":     int(total_users or 0),
        }
    finally:
        db.close()

@app.get("/admin/users", tags=["Admin"])
def get_admin_users(user_id: str):
    require_admin(user_id)
    db = SessionLocal()
    try:
        today = date.today().isoformat()
        rows = db.execute(text("""
            SELECT
                user_email,
                user_id,
                COUNT(*) AS total_scans,
                COUNT(*) FILTER (WHERE DATE(created_at) = :today) AS scans_today,
                MIN(created_at) AS joined_at
            FROM scans
            WHERE user_id IS NOT NULL
            GROUP BY user_email, user_id
            ORDER BY joined_at DESC
        """), {"today": today}).fetchall()

        users = []
        for row in rows:
            is_admin_user = scan_store.is_admin(row[1])
            limit_row = db.execute(text("""
                SELECT daily_limit FROM user_scan_limits
                WHERE user_id = :uid AND scan_date = :today
            """), {"uid": row[1], "today": today}).fetchone()
            users.append({
                "email":            row[0],
                "user_id":          row[1],
                "total_scans":      int(row[2]),
                "scans_today":      int(row[3]),
                "joined_at":        str(row[4]),
                "role":             "admin" if is_admin_user else "user",
                "scanning_disabled": limit_row[0] == 0 if limit_row else False,
            })
        return {"users": users, "total": len(users)}
    finally:
        db.close()


@app.get("/admin/scans", tags=["Admin"])
def get_admin_scans(user_id: str, limit: int = 50, offset: int = 0):
    require_admin(user_id)
    db = SessionLocal()
    try:
        from db.models import Scan as ScanModel
        scans = db.query(ScanModel).order_by(
            ScanModel.created_at.desc()
        ).offset(offset).limit(limit).all()
        total = db.query(ScanModel).count()
        return {
            "scans": [
                {
                    "scan_id":      s.scan_id,
                    "url":          s.url,
                    "user_email":   s.user_email,
                    "user_id":      s.user_id,
                    "status":       s.status,
                    "created_at":   s.created_at,
                    "completed_at": s.completed_at,
                    "summary":      s.summary or {},
                    "error":        s.error,
                }
                for s in scans
            ],
            "total": total,
        }
    finally:
        db.close()


@app.post("/admin/users/{target_user_id}/disable-scanning", tags=["Admin"])
def disable_user_scanning(target_user_id: str, user_id: str):
    require_admin(user_id)
    db = SessionLocal()
    try:
        today = date.today()
        db.execute(text("""
            INSERT INTO user_scan_limits (user_id, email, scan_date, scan_count, daily_limit)
            VALUES (:uid, '', :today, 0, 0)
            ON CONFLICT (user_id, scan_date)
            DO UPDATE SET daily_limit = 0
        """), {"uid": target_user_id, "today": today})
        db.commit()
        return {"message": f"Scanning disabled for user {target_user_id}"}
    finally:
        db.close()


@app.post("/admin/users/{target_user_id}/enable-scanning", tags=["Admin"])
def enable_user_scanning(target_user_id: str, user_id: str):
    require_admin(user_id)
    db = SessionLocal()
    try:
        today = date.today()
        db.execute(text("""
            INSERT INTO user_scan_limits (user_id, email, scan_date, scan_count, daily_limit)
            VALUES (:uid, '', :today, 0, 3)
            ON CONFLICT (user_id, scan_date)
            DO UPDATE SET daily_limit = 3
        """), {"uid": target_user_id, "today": today})
        db.commit()
        return {"message": f"Scanning enabled for user {target_user_id}"}
    finally:
        db.close()


@app.post("/admin/users/{target_user_id}/reset-limit", tags=["Admin"])
def reset_user_limit(target_user_id: str, user_id: str):
    require_admin(user_id)
    db = SessionLocal()
    try:
        today = date.today()
        db.execute(text("""
            UPDATE user_scan_limits
            SET scan_count = 0
            WHERE user_id = :uid AND scan_date = :today
        """), {"uid": target_user_id, "today": today})
        db.commit()
        return {"message": f"Scan limit reset for user {target_user_id}"}
    finally:
        db.close()


@app.get("/admin/health", tags=["Admin"])
def get_system_health(user_id: str):
    require_admin(user_id)
    health = {}
    health["fastapi"] = {"status": "healthy"}
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        health["postgresql"] = {"status": "healthy"}
    except Exception as e:
        health["postgresql"] = {"status": "unhealthy", "error": str(e)}
    try:
        import redis as redis_lib
        r = redis_lib.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        health["redis"] = {"status": "healthy"}
    except Exception as e:
        health["redis"] = {"status": "unhealthy", "error": str(e)}
    try:
        import requests as req
        resp = req.get(
            f"{os.getenv('ZAP_URL', 'http://localhost:8080')}/JSON/core/view/version/",
            timeout=5
        )
        health["zap"] = {"status": "healthy", "version": resp.json().get("version")}
    except Exception as e:
        health["zap"] = {"status": "unhealthy", "error": str(e)}
    try:
        from api.celery_app import celery_app
        i = celery_app.control.inspect(timeout=3)
        health["celery"] = {"status": "healthy" if i.active() is not None else "unhealthy"}
    except Exception as e:
        health["celery"] = {"status": "unhealthy", "error": str(e)}
    return health
# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Vulnerability Assessment API is running"}


@app.post("/scans", response_model=ScanResponse, tags=["Scans"])
def create_scan(request: ScanRequest ):
    """
    Submit a URL for vulnerability scanning.
    
    - Returns a scan_id immediately (async — scan runs in background)
    - Poll GET /scans/{scan_id} to check progress and get results
    
    The scan pipeline:
        1. Spider scan (passive — crawls all links)
        2. Active scan (sends payloads — SQLi, XSS, etc.)
        3. CVSS + OWASP Top 10 mapping
        4. AI analysis (remediation + business impact)
    """
    scan_id = str(uuid.uuid4())
    target_url = str(request.url)

    # Validate URL has a scheme
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    # ── Daily limit check ──────────────────────
    user_id    = getattr(request, "user_id", None)
    user_email = getattr(request, "user_email", None)

    if user_id:
        allowed, count = check_and_increment_scan_limit(user_id, user_email or "")
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Daily scan limit reached (3 scans/day). Resets at midnight UTC."
            )
        
    # Initialize scan record in store
    scan_store[scan_id] = {
        "scan_id":    scan_id,
        "url":        target_url,
        "status":     ScanStatus.QUEUED,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "findings":   [],
        "summary":    {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "executive_summary": "",
        "user_id":           request.user_id,
        "user_email":        request.user_email,
        "progress":           0,
        "stage":              "Queued",
        "error":      None,
    }

    # Run scan in background (Phase 1: no Celery yet — uses FastAPI BackgroundTasks)
    # In Phase 2 this becomes: celery_task.delay(scan_id, target_url)
    from api.celery_tasks import run_scan_celery
    run_scan_celery.delay(scan_id, target_url)

    audit_logger.log_event(
        event_type="SCAN_CREATED",
        performed_by=user_id,
        entity_type="scan",
        entity_id=scan_id,
        action=f"Scan created for {target_url}",
        metadata={"url": target_url},
    )

    return ScanResponse(
        scan_id=scan_id,
        url=target_url,
        status=ScanStatus.QUEUED,
        message=f"Scan queued. Poll GET /scans/{scan_id} for status and results.",
    )


@app.get("/scans/{scan_id}", response_model=ScanStatusResponse, tags=["Scans"])
def get_scan(scan_id: str, user_id: Optional[str] = None):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if user_id and scan.get("user_id") and scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return scan

@app.get("/scans/{scan_id}/progress", tags=["Scans"])
def get_scan_progress(scan_id: str):
    """Get real-time scan progress for the progress bar."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan["status"]
    
    # Estimate progress based on status and elapsed time
    if status == "queued":
        return {"progress": 0, "stage": "Queued — waiting to start", "estimated_seconds_left": None}
    elif status == "completed":
        return {"progress": 100, "stage": "Scan complete", "estimated_seconds_left": 0}
    elif status == "failed":
        return {"progress": 0, "stage": "Scan failed", "estimated_seconds_left": None}
    
    # Status is "running" — estimate based on elapsed time
    # Average full scan takes ~180 seconds
    try:
        from datetime import datetime
        created = datetime.fromisoformat(scan["created_at"])
        elapsed = (datetime.utcnow() - created).total_seconds()
        ESTIMATED_TOTAL = 180
        progress = min(int((elapsed / ESTIMATED_TOTAL) * 90), 90)  # cap at 90% until actually done
        seconds_left = max(int(ESTIMATED_TOTAL - elapsed), 0)
        
        # Stage labels based on progress
        if progress < 15:
            stage = "Starting ZAP scanner..."
        elif progress < 30:
            stage = "Spider crawling target..."
        elif progress < 70:
            stage = "Active scanning — testing for SQLi, XSS, CSRF..."
        elif progress < 80:
            stage = "Running Nuclei templates..."
        elif progress < 85:
            stage = "Checking SSL/TLS and HTTP headers..."
        else:
            stage = "AI enrichment — generating recommendations..."
        
        return {
            "progress": progress,
            "stage": stage,
            "estimated_seconds_left": seconds_left
        }
    except Exception:
        return {"progress": 50, "stage": "Scanning in progress...", "estimated_seconds_left": None}

@app.get("/scans", response_model=ScanListResponse, tags=["Scans"])
def list_scans(user_id: str):
    """List scans for a specific user only."""
    scans = scan_store.values_by_user(user_id)
    return {"scans": scans, "total": len(scans)}

@app.delete("/scans/{scan_id}", tags=["Scans"])
def delete_scan(scan_id: str):
    """Delete a scan record."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    del scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


@app.get("/scans/{scan_id}/report/pdf", tags=["Reports"])
def download_pdf(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    generator = PDFGenerator()
    path = generator.generate(scan, output_filename=f"report_{scan_id}.pdf")
    audit_logger.log_event(
        event_type="REPORT_DOWNLOADED",
        performed_by=scan.get("user_id"),
        entity_type="scan",
        entity_id=scan_id,
        action=f"PDF report downloaded for {scan.get('url')}",
        metadata={"format": "pdf", "url": scan.get("url")},
        )
    return FileResponse(path, media_type="application/pdf", filename=f"report_{scan_id}.pdf")

@app.get("/scans/{scan_id}/report/excel", tags=["Reports"])
def download_excel(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    generator = ExcelGenerator()
    path = generator.generate(scan, output_filename=f"report_{scan_id}.xlsx")
    audit_logger.log_event(
        event_type="REPORT_DOWNLOADED",
        performed_by=scan.get("user_id"),
        entity_type="scan",
        entity_id=scan_id,
        action=f"Excel report downloaded for {scan.get('url')}",
        metadata={"format": "xlsx", "url": scan.get("url")},
        )

    return FileResponse(path, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=f"report_{scan_id}.xlsx")

@app.get("/limits/{user_id}", tags=["Limits"])
def get_user_limits(user_id: str):
    """Get remaining scans for today."""
    from db.database import SessionLocal
    db = SessionLocal()
    try:
        today = date.today()
        row = db.execute(text("""
            SELECT scan_count, daily_limit
            FROM user_scan_limits
            WHERE user_id = :user_id AND scan_date = :today
        """), {"user_id": user_id, "today": today}).fetchone()

        if not row:
            return {"scans_used": 0, "daily_limit": 3, "scans_remaining": 3}

        return {
            "scans_used":      row[0],
            "daily_limit":     row[1],
            "scans_remaining": max(0, row[1] - row[0]),
        }
    finally:
        db.close()

@app.get("/admin/logs/api", tags=["Admin"])
def get_api_logs(user_id: str, limit: int = 100):
    require_admin(user_id)
    db = SessionLocal()
    try:
        from db.models import ApiLog
        logs = db.query(ApiLog).order_by(
            ApiLog.timestamp.desc()
        ).limit(limit).all()
        return {
            "logs": [
                {
                    "id":                l.id,
                    "request_id":        l.request_id,
                    "timestamp":         l.timestamp,
                    "method":            l.method,
                    "endpoint":          l.endpoint,
                    "user_id":           l.user_id,
                    "ip_address":        l.ip_address,
                    "response_status":   l.response_status,
                    "execution_time_ms": l.execution_time_ms,
                    "success":           l.success,
                    "error_message":     l.error_message,
                }
                for l in logs
            ],
            "total": db.query(ApiLog).count(),
        }
    finally:
        db.close()


@app.get("/admin/logs/audit", tags=["Admin"])
def get_audit_logs(user_id: str, limit: int = 100):
    require_admin(user_id)
    db = SessionLocal()
    try:
        from db.models import AuditLog
        logs = db.query(AuditLog).order_by(
            AuditLog.timestamp.desc()
        ).limit(limit).all()
        return {
            "logs": [
                {
                    "id":             l.id,
                    "timestamp":      l.timestamp,
                    "event_type":     l.event_type,
                    "performed_by":   l.performed_by,
                    "entity_type":    l.entity_type,
                    "entity_id":      l.entity_id,
                    "action":         l.action,
                    "event_metadata": l.event_metadata,
                    "ip_address":     l.ip_address,
                }
                for l in logs
            ],
            "total": db.query(AuditLog).count(),
        }
    finally:
        db.close()


@app.get("/admin/logs/errors", tags=["Admin"])
def get_error_logs(user_id: str, limit: int = 50):
    require_admin(user_id)
    db = SessionLocal()
    try:
        from db.models import ErrorLog
        logs = db.query(ErrorLog).order_by(
            ErrorLog.timestamp.desc()
        ).limit(limit).all()
        return {
            "logs": [
                {
                    "id":                l.id,
                    "timestamp":         l.timestamp,
                    "request_id":        l.request_id,
                    "endpoint":          l.endpoint,
                    "exception_type":    l.exception_type,
                    "exception_message": l.exception_message,
                    "user_id":           l.user_id,
                    "ip_address":        l.ip_address,
                }
                for l in logs
            ],
            "total": db.query(ErrorLog).count(),
        }
    finally:
        db.close()