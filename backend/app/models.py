"""ORM models for SentinelOps SIEM."""
from datetime import datetime
from sqlalchemy import Column, Integer, BigInteger, String, Float, Boolean, DateTime, Text, Index
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)   # pbkdf2$iter$salt$hash
    role = Column(String(12), default="viewer")           # admin / analyst / viewer
    api_token = Column(String(64), index=True)            # for programmatic/MCP access
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

    def to_dict(self):
        return {"id": self.id, "username": self.username, "email": self.email,
                "role": self.role, "active": self.active,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "last_login": self.last_login.isoformat() if self.last_login else None}


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(40))
    action = Column(String(60))
    detail = Column(String(255))
    ip = Column(String(45))

    def to_dict(self):
        return {"id": self.id, "ts": self.ts.isoformat() if self.ts else None,
                "actor": self.actor, "action": self.action, "detail": self.detail, "ip": self.ip}


class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(BigInteger, index=True)          # epoch millis
    sourcetype = Column(String(40), index=True)
    host = Column(String(40), index=True)
    severity = Column(String(12), index=True)
    action = Column(String(20), index=True)
    user = Column(String(40), index=True)
    src_ip = Column(String(45), index=True)
    dest_ip = Column(String(45))
    dest_port = Column(Integer)
    protocol = Column(String(8))
    status = Column(Integer)
    method = Column(String(8))
    uri = Column(String(255))
    bytes = Column(BigInteger)
    country = Column(String(4), index=True)
    user_agent = Column(String(120))
    process = Column(String(60))
    parent = Column(String(60))
    event_id = Column(Integer)
    logon_type = Column(Integer)
    signature = Column(String(120))
    event_name = Column(String(60))
    policy = Column(String(60))
    service = Column(String(30))
    query = Column(String(120))
    record = Column(String(8))
    raw = Column(Text)

    def to_dict(self):
        d = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        d["_id"] = d.pop("id")
        d["_time"] = d.pop("ts")
        d["_raw"] = d.pop("raw")
        return {k: v for k, v in d.items() if v is not None}


Index("ix_events_src_action", Event.src_ip, Event.action)


class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    description = Column(String(255))
    severity = Column(String(12))
    enabled = Column(Boolean, default=True)
    icon = Column(String(8))
    detector = Column(String(40))   # key linking to detect.py functions


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    fid = Column(String(16), index=True)
    title = Column(String(160))
    severity = Column(String(12), index=True)
    tactic = Column(String(60))
    mitre = Column(String(40))
    confidence = Column(Integer)
    src_ip = Column(String(45))
    country = Column(String(4))
    host = Column(String(40))
    evidence = Column(Text)
    recommendation = Column(Text)
    count = Column(Integer)
    detector = Column(String(40))
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.fid, "title": self.title, "severity": self.severity,
            "tactic": self.tactic, "mitre": self.mitre, "confidence": self.confidence,
            "src_ip": self.src_ip, "country": self.country, "host": self.host,
            "evidence": self.evidence, "recommendation": self.recommendation,
            "count": self.count, "detector": self.detector,
        }


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    finding_id = Column(String(16))
    title = Column(String(160))
    severity = Column(String(12))
    status = Column(String(20), default="open")   # open / investigating / resolved
    assignee = Column(String(40), default="unassigned")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "finding_id": self.finding_id, "title": self.title,
            "severity": self.severity, "status": self.status, "assignee": self.assignee,
            "notes": self.notes, "created_at": self.created_at.isoformat() if self.created_at else None,
        }
