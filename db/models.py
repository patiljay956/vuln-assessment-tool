"""
Database Models
===============
SQLAlchemy ORM models for PostgreSQL persistence.
"""

from sqlalchemy import Column, String, Text, Float, DateTime, JSON
from sqlalchemy.orm import DeclarativeBase
import datetime
import uuid

class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    scan_id           = Column(String,   primary_key=True)
    url               = Column(String,   nullable=False)
    status            = Column(String,   default="queued")
    created_at        = Column(String,   nullable=False)
    completed_at      = Column(String,   nullable=True)
    findings          = Column(JSON,     default=list)
    summary           = Column(JSON,     default=dict)
    executive_summary = Column(Text,     default="")
    error             = Column(Text,     nullable=True) 
    user_id           = Column(String, nullable=True)
    user_email        = Column(String, nullable=True)

class Admin(Base):
    __tablename__ = "admins"

    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, nullable=False, unique=True)
    email      = Column(String, nullable=False, unique=True)
    created_at = Column(String, default=lambda: datetime.datetime.utcnow().isoformat())

class ApiLog(Base):
    __tablename__ = "api_logs"

    id                = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id        = Column(String, nullable=False)
    timestamp         = Column(String, nullable=False)
    method            = Column(String, nullable=False)
    endpoint          = Column(String, nullable=False)
    full_url          = Column(String, nullable=False)
    path_params       = Column(JSON, default=dict)
    query_params      = Column(JSON, default=dict)
    request_body      = Column(JSON, nullable=True)
    user_id           = Column(String, nullable=True)
    username          = Column(String, nullable=True)
    role              = Column(String, nullable=True)
    ip_address        = Column(String, nullable=True)
    user_agent        = Column(String, nullable=True)
    response_status   = Column(String, nullable=True)
    response_size     = Column(String, nullable=True)
    execution_time_ms = Column(String, nullable=True)
    success           = Column(String, nullable=True)
    error_message     = Column(String, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp    = Column(String, nullable=False)
    event_type   = Column(String, nullable=False)
    performed_by = Column(String, nullable=True)
    entity_type  = Column(String, nullable=True)
    entity_id    = Column(String, nullable=True)
    action       = Column(String, nullable=True)
    event_metadata   = Column(JSON, nullable=True)
    ip_address   = Column(String, nullable=True)


class ErrorLog(Base):
    __tablename__ = "error_logs"

    id                = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp         = Column(String, nullable=False)
    request_id        = Column(String, nullable=True)
    endpoint          = Column(String, nullable=True)
    exception_type    = Column(String, nullable=True)
    exception_message = Column(String, nullable=True)
    stack_trace       = Column(Text, nullable=True)
    user_id           = Column(String, nullable=True)
    ip_address        = Column(String, nullable=True)