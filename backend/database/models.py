import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, JSON, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String(255), primary_key=True)  # Generated locally at registration
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(512), nullable=True)  # PBKDF2-HMAC-SHA256; NULL for legacy/historical rows
    role = Column(String(50), nullable=False, default="user")  # "admin" | "user"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    user_id = Column(String(255), ForeignKey("users.id"), nullable=False)
    scope_json = Column(JSON, default=list)  # List of authorized targets (domains, IPs, CIDRs) owned by the user
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="projects")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 of the opaque token
    user_id = Column(String(255), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="sessions")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    type = Column(String(50), nullable=False)  # "domain", "ip", "port", "tech"
    value = Column(String(255), nullable=False)  # e.g., "api.target.com", "192.168.1.1", "80/tcp"
    metadata_json = Column(JSON, default=dict)  # e.g., technology details, port status
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="assets")


class Scan(Base):
    """A single security assessment job (Phase 4: job lifecycle model).

    ``status`` is the coarse, terminal-compatible state used across the API
    (Pending/Running/Completed/Failed/Cancelled). ``stage`` tracks the detailed
    job lifecycle (queued/starting/recon/discovery/service_scan/http_scan/
    vulnerability_scan/analysis/reporting) and is the source of progress events.
    ``progress`` and ``coverage`` are structured, persisted progress metadata and
    are never fabricated: counters increment only from real stage/tool completions.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target = Column(String(255), nullable=False)  # IP, domain, or CIDR
    status = Column(String(50), default="Pending")  # "Pending", "Running", "Completed", "Failed", "Cancelled"
    stage = Column(String(50), default="queued")  # job lifecycle stage (see app.agents.lifecycle)
    progress = Column(JSON, default=dict)  # {completed_tasks, total_tasks, completed_tools, total_tools, ...}
    coverage = Column(Float, nullable=True)  # assessment coverage % (0-100), distinct from risk score
    scan_config = Column(JSON, default=dict)  # enabled tools / severity profile captured at trigger
    cancel_requested = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    security_score = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    logs = Column(Text, default="")  # Live streamed execution logs

    project = relationship("Project", back_populates="scans")
    tool_results = relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    observations = relationship("Observation", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    chats = relationship("ChatHistory", back_populates="scan", cascade="all, delete-orphan")


class ToolResult(Base):
    __tablename__ = "tool_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # "nmap", "nuclei", "subfinder", etc.
    status = Column(String(50), default="Pending")  # "Running", "Completed", "Failed"
    raw_output = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="tool_results")


class Vulnerability(Base):
    """A persisted security finding.

    Phase 3: a finding is never fabricated.  Every finding carries a rule_id,
    a triage state, and the evidence trail (human-readable ``evidence`` text
    plus the ids of the persisted ``Observation`` rows it was derived from).
    The chain finding -> evidence -> observation -> tool -> scan -> authorized
    target is therefore fully traceable in the database.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # "Critical", "High", "Medium", "Low", "Info"
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    cve = Column(String(100), nullable=True)
    cvss = Column(Float, nullable=True)
    owasp = Column(String(100), nullable=True)
    mitre = Column(String(100), nullable=True)
    cwe = Column(String(100), nullable=True)
    target = Column(String(255), nullable=True)  # URL/IP where it was found
    proof_of_concept = Column(Text, nullable=True)
    rule_id = Column(String(100), nullable=True)  # deterministic rule that produced this finding
    dedup_key = Column(String(255), nullable=True)  # stable identity used for duplicate suppression
    confidence = Column(String(20), nullable=True)  # "intermediate" | "confirmed"
    state = Column(String(50), nullable=False, default="NEW")  # NEW/CONFIRMED/FALSE_POSITIVE/DUPLICATE/ACCEPTED_RISK/RESOLVED
    evidence = Column(Text, nullable=True)  # human-readable support trail for the finding
    evidence_observation_ids = Column(JSON, nullable=True)  # ids of supporting Observation rows
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")


class Observation(Base):
    """A single, plugin-faithful factual observation captured by a real tool.

    Observations are the only accepted source of evidence in Phase 3: findings
    are derived exclusively from rows here.  ``kind`` names what was measured
    (e.g. ``dns_record``, ``tcp_connect``, ``http_response``), ``subject`` is
    the host/endpoint it measured, ``data_json`` holds the structured facts and
    ``raw_output`` the verbatim evidence snippet (response headers, resolved IP,
    DNS error, ...).  A probe that could not complete is recorded as an
    observation too (e.g. ``dns_error``, ``http_error``) so "nothing to report"
    is itself evidenced rather than silently dropped.
    """
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # which real tool/probe captured it
    kind = Column(String(50), nullable=False)
    subject = Column(String(255), nullable=False)  # host / endpoint the fact concerns
    data_json = Column(JSON, default=dict)
    raw_output = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="observations")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    pdf_content = Column(LargeBinary, nullable=True)  # Store report files or mock bytes
    markdown_content = Column(Text, nullable=True)
    json_content = Column(JSON, nullable=True)
    html_content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    role = Column(String(50), nullable=False)  # "user", "assistant"
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="chats")
