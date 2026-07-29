"""
Audit Logger Service
====================
Records business events to audit_logs table.
Use for: scan lifecycle, report downloads, admin actions, auth events.
"""

import uuid
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    def log_event(
        self,
        event_type: str,
        performed_by: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        action: Optional[str] = None,
        metadata: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ):
        """
        Log a business event.

        Args:
            event_type:   e.g. SCAN_CREATED, REPORT_DOWNLOADED, ADMIN_LOGIN
            performed_by: user_id of the actor
            entity_type:  e.g. "scan", "report", "user"
            entity_id:    ID of the affected entity
            action:       short description e.g. "created scan for https://..."
            metadata:     additional JSON context
            ip_address:   actor's IP
        """
        try:
            from db.database import SessionLocal
            from db.models import AuditLog

            db = SessionLocal()
            try:
                log = AuditLog(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow().isoformat(),
                    event_type=event_type,
                    performed_by=performed_by,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    action=action,
                    event_metadata=metadata or {},
                    ip_address=ip_address,
                )
                db.add(log)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"AuditLogger.log_event failed (non-fatal): {e}")


audit_logger = AuditLogger()