"""
Logging Middleware
==================
Automatically logs every HTTP request and response.
Extracts request_id, timing, user info, and response metadata
without modifying any individual endpoint.
"""

import uuid
import time
import json
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

SKIP_ENDPOINTS = {"/", "/docs", "/openapi.json", "/redoc"}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip health check and docs endpoints
        if request.url.path in SKIP_ENDPOINTS:
            return await call_next(request)

        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Extract request body safely
        request_body = None
        try:
            if request.method in ("POST", "PUT", "PATCH"):
                body_bytes = await request.body()
                if body_bytes:
                    request_body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            pass

        # Extract user_id from query params if present
        user_id = request.query_params.get("user_id")

        # Process request
        response = await call_next(request)

        execution_time_ms = (time.time() - start_time) * 1000
        success = response.status_code < 400

        # Get response size
        response_size = int(response.headers.get("content-length", 0))

        # Get client IP
        ip_address = request.headers.get("x-forwarded-for", request.client.host if request.client else None)

        # Write log (non-blocking failure)
        try:
            from services.api_logger import api_logger
            api_logger.write(
                request_id=request_id,
                method=request.method,
                endpoint=request.url.path,
                full_url=str(request.url),
                path_params=dict(request.path_params),
                query_params=dict(request.query_params),
                request_body=request_body,
                user_id=user_id,
                username=None,
                role=None,
                ip_address=ip_address,
                user_agent=request.headers.get("user-agent"),
                response_status=response.status_code,
                response_size=response_size,
                execution_time_ms=execution_time_ms,
                success=success,
                error_message=None if success else f"HTTP {response.status_code}",
            )
        except Exception as e:
            logger.warning(f"Middleware logging failed (non-fatal): {e}")

        # Attach request_id to response headers for traceability
        response.headers["X-Request-ID"] = request_id
        return response