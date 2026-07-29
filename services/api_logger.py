"""
API Logger Service
==================
Writes HTTP request/response records to api_logs table.
Failures never break the API — all writes are wrapped in try/except.
"""

import uuid
import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

SENSITIVE_FIELDS = {
    "password", "token", "secret", "api_key", "apikey",
    "authorization", "cookie", "access_token", "refresh_token",
    "private_key", "client_secret",
}


def mask_sensitive(data: dict) -> dict:
    """Recursively mask sensitive fields in a dict."""
    if not isinstance(data, dict):
        return data
    masked = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_FIELDS:
            masked[key] = "***MASKED***"
        elif isinstance(value, dict):
            masked[key] = mask_sensitive(value)
        else:
            masked[key] = value
    return masked


class ApiLogger:
    def write(
        self,
        request_id: str,
        method: str,
        endpoint: str,
        full_url: str,
        path_params: dict,
        query_params: dict,
        request_body: Optional[dict],
        user_id: Optional[str],
        username: Optional[str],
        role: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        response_status: int,
        response_size: int,
        execution_time_ms: float,
        success: bool,
        error_message: Optional[str] = None,
    ):
        try:
            from db.database import SessionLocal
            from db.models import ApiLog

            db = SessionLocal()
            try:
                log = ApiLog(
                    id=str(uuid.uuid4()),
                    request_id=request_id,
                    timestamp=datetime.utcnow().isoformat(),
                    method=method,
                    endpoint=endpoint,
                    full_url=full_url,
                    path_params=path_params or {},
                    query_params=mask_sensitive(query_params or {}),
                    request_body=mask_sensitive(request_body) if request_body else None,
                    user_id=user_id,
                    username=username,
                    role=role,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    response_status=str(response_status),
                    response_size=str(response_size),
                    execution_time_ms=str(round(execution_time_ms, 2)),
                    success=str(success),
                    error_message=error_message,
                )
                db.add(log)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"ApiLogger.write failed (non-fatal): {e}")


api_logger = ApiLogger()