"""
Global Exception Handler
========================
Catches unhandled exceptions, logs them to error_logs,
then returns a clean JSON error response.
"""

import uuid
import logging
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    user_id = request.query_params.get("user_id")
    ip_address = request.headers.get(
        "x-forwarded-for",
        request.client.host if request.client else None
    )

    try:
        from services.error_logger import error_logger
        error_logger.log_error(
            exception=exc,
            request_id=request_id,
            endpoint=request.url.path,
            user_id=user_id,
            ip_address=ip_address,
        )
    except Exception as log_err:
        logger.warning(f"Exception handler logging failed (non-fatal): {log_err}")

    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "request_id": request_id,
        }
    )