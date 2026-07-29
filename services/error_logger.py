"""
Error Logger Service
====================
Records unhandled exceptions to error_logs table.
Called by the global exception handler.
"""

import uuid
import traceback
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class ErrorLogger:
    def log_error(
        self,
        exception: Exception,
        request_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        try:
            from db.database import SessionLocal
            from db.models import ErrorLog

            db = SessionLocal()
            try:
                log = ErrorLog(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow().isoformat(),
                    request_id=request_id,
                    endpoint=endpoint,
                    exception_type=type(exception).__name__,
                    exception_message=str(exception),
                    stack_trace=traceback.format_exc(),
                    user_id=user_id,
                    ip_address=ip_address,
                )
                db.add(log)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"ErrorLogger.log_error failed (non-fatal): {e}")


error_logger = ErrorLogger()