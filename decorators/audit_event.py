"""
Audit Event Decorator
=====================
Use to automatically log business events around endpoint functions.

Usage:
    @audit_event("SCAN_CREATED", entity_type="scan")
    def create_scan(...):
        ...
"""

import functools
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def audit_event(
    event_type: str,
    entity_type: Optional[str] = None,
):
    """
    Decorator that logs an audit event when the decorated function succeeds.

    The decorated function should have a `request` parameter (FastAPI Request)
    OR a `user_id` query param for the actor to be captured.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            from services.audit_logger import audit_logger

            result = func(*args, **kwargs)

            # Try to extract user_id from kwargs
            user_id = kwargs.get("user_id")
            request = kwargs.get("request")
            ip_address = None

            if request:
                ip_address = request.headers.get(
                    "x-forwarded-for",
                    request.client.host if request.client else None
                )

            try:
                audit_logger.log_event(
                    event_type=event_type,
                    performed_by=user_id,
                    entity_type=entity_type,
                    action=f"{event_type} via {func.__name__}",
                    ip_address=ip_address,
                )
            except Exception as e:
                logger.warning(f"audit_event decorator failed (non-fatal): {e}")

            return result
        return wrapper
    return decorator