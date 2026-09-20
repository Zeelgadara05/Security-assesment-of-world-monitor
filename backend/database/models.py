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
    assessment_tests = relationship("AssessmentTest", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    chats = relationship("ChatHistory", back_populates="scan", cascade="all, delete-orphan")
    report_exports = relationship("ReportExport", back_populates="scan", cascade="all, delete-orphan")

    # Phase 6 assessment completeness (never a security verdict).
    assessment_status = Column(String(50), nullable=True)  # not_started|running|completed|completed_with_gaps|failed
    assessment_completeness = Column(String(50), nullable=True)  # complete|partial|minimal|unknown
    assessment_snapshot_json = Column(JSON, nullable=True)  # config snapshot + reproducibility metadata


class ToolResult(Base):
    """Per-tool execution record.

    Phase 4 persisted the coarse status + raw output.  Phase 5 adds execution
    telemetry (version, redacted command, timing, exit code, output sizes and
    how many observations the run parsed).  Commands stored here are always
    redacted: no secrets, tokens, cookies or credentials are persisted.
    """
    __tablename__ = "tool_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # "nmap", "nuclei", "subfinder", etc.
    status = Column(String(50), default="Pending")  # "Running", "Completed", "Failed"
    raw_output = Column(Text, default="")
    tool_version = Column(String(100), nullable=True)
    command_redacted = Column(Text, nullable=True)  # argument list with secrets redacted
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    exit_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    stdout_size = Column(Integer, nullable=True)
    stderr_size = Column(Integer, nullable=True)
    parsed_observations = Column(Integer, default=0)
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
    confidence = Column(String(20), nullable=True)  # Phase 3: "intermediate" | "confirmed"; Phase 5: LOW/MEDIUM/HIGH/CONFIRMED
    state = Column(String(50), nullable=False, default="NEW")  # NEW/CONFIRMED/FALSE_POSITIVE/DUPLICATE/ACCEPTED_RISK/RESOLVED
    # Phase 5 assessment metadata (all optional; existing Phase 3 rows remain valid).
    category = Column(String(100), nullable=True)  # vulnerability class, e.g. "authorization", "xss"
    endpoint = Column(String(512), nullable=True)  # normalized endpoint the finding concerns
    http_method = Column(String(20), nullable=True)  # GET/POST/...
    source_test = Column(String(100), nullable=True)  # security test id that produced the candidate
    source_tool = Column(String(100), nullable=True)  # observation-producing tool/probe
    validation_reason = Column(Text, nullable=True)  # deterministic reason for confirm/reject
    impact = Column(Text, nullable=True)  # documented impact statement
    evidence = Column(Text, nullable=True)  # human-readable support trail for the finding
    evidence_observation_ids = Column(JSON, nullable=True)  # ids of supporting Observation rows
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Phase 6 finding lifecycle + reporting (all optional/nullable).
    # status: candidate|validated|confirmed|rejected|duplicate|accepted|remediated|reopened
    status = Column(String(50), nullable=False, default="confirmed", index=True)
    affected_component = Column(String(100), nullable=True)  # e.g. "backend/api", "tls", "oauth"
    parameter = Column(String(255), nullable=True)
    cvss_version = Column(String(10), nullable=True)  # "3.1" when a vector is present
    cvss_vector = Column(String(255), nullable=True)  # full CVSS vector, never fabricated
    cvss_score = Column(Float, nullable=True)  # deterministic base score derived from the vector
    business_impact = Column(Text, nullable=True)
    technical_impact = Column(Text, nullable=True)
    impact_details = Column(JSON, nullable=True)  # structured technical/business impact factors
    remediation_details = Column(JSON, nullable=True)  # summary/technical_fix/configuration_fix/validation_steps/regression_test
    references_json = Column(JSON, nullable=True)  # deterministic reference list
    fingerprint = Column(String(64), nullable=True, index=True)  # finding identity for dedup/control
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")
    evidence_records = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    status_history = relationship("FindingStatusHistory", back_populates="finding", cascade="all, delete-orphan")


class Observation(Base):
    """A single, plugin-faithful factual observation captured by a real tool.

    Observations are the only accepted source of evidence: findings are derived
    exclusively from rows here.  ``kind`` names what was measured (e.g.
    ``dns_record``, ``tcp_connect``, ``http_response``), ``subject`` is the
    host/endpoint it measured, ``data_json`` holds the structured facts and
    ``raw_output`` the verbatim evidence snippet (response headers, resolved IP,
    DNS error, ...).  A probe that could not complete is recorded as an
    observation too (e.g. ``dns_error``, ``http_error``) so "nothing to report"
    is itself evidenced rather than silently dropped.

    Phase 5 enriches each observation with an explicit ``observation_type``,
    the owning ``user_id`` (denormalized so isolation can be queried directly),
    the normalized ``target``/``asset``, an optional structured
    ``request_json``/``response_json`` pair (headers redacted before storage),
    ``fingerprint`` for stable deduplication, and a ``status``/``source``.
    """
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # which real tool/probe captured it
    kind = Column(String(50), nullable=False)
    subject = Column(String(255), nullable=False)  # host / endpoint the fact concerns
    data_json = Column(JSON, default=dict)
    raw_output = Column(Text, default="")
    # Phase 5 assessment fields (all optional/nullable for Phase 3 compatibility).
    user_id = Column(String(255), nullable=True)  # owner of the scan (denormalized)
    target = Column(String(255), nullable=True)  # normalized authorized target
    asset = Column(String(255), nullable=True)  # host/asset the observation belongs to
    observation_type = Column(String(50), nullable=True)  # see app.observations.types
    source = Column(String(100), nullable=True)  # e.g. "external_tool", "http_client", "stdlib_probe"
    tool_version = Column(String(100), nullable=True)
    request_json = Column(JSON, nullable=True)  # structured HTTP request (redacted)
    response_json = Column(JSON, nullable=True)  # structured HTTP response (redacted)
    metadata_json = Column(JSON, nullable=True)
    fingerprint = Column(String(64), nullable=True)  # stable SHA-256 of the observation identity
    status = Column(String(50), nullable=True)  # observed | error | skipped | ...
    observed_at = Column(DateTime, nullable=True)
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


class AssessmentTest(Base):
    """Deterministic record of one planned/executed security test on a scan.

    Phase 5 planning persists every test the planner considered so coverage is
    auditable: which tests were planned, applicable, skipped (and exactly why),
    executed, validated, or failed.  ``reason`` is always a concrete,
    deterministic explanation (never an LLM rationale).  A test is only counted
    as executed when it actually ran, and only counted as validated when the
    validator reached a confirmed/rejected verdict.
    """
    __tablename__ = "assessment_tests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    test_id = Column(String(100), nullable=False)  # stable test identifier, e.g. "http.security_headers"
    name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)  # vulnerability class, e.g. "xss", "authorization"
    status = Column(String(50), nullable=False, default="planned")
    # planned | not_applicable | skipped | executed | validated | failed | rejected
    reason = Column(Text, nullable=True)  # deterministic reason for the status
    target = Column(String(255), nullable=True)
    endpoint = Column(String(512), nullable=True)
    http_method = Column(String(20), nullable=True)
    active = Column(Boolean, default=False)  # True when the test mutates state
    required_observations = Column(JSON, nullable=True)  # observation types the test consumed
    required_capabilities = Column(JSON, nullable=True)  # tool/native capabilities required
    observation_ids = Column(JSON, nullable=True)  # observations produced by this test
    finding_ids = Column(JSON, nullable=True)  # findings created/confirmed by this test
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="assessment_tests")


class FindingEvidence(Base):
    """Structured evidence backing a finding.

    Each record links a finding to the observation(s) that prove it and stores
    the expected-vs-actual security-property comparison.  ``request_json`` and
    ``response_json`` are always redacted before persistence (no cookies,
    Authorization headers, API keys or tokens are ever stored in cleartext).
    """
    __tablename__ = "finding_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=True)
    evidence_type = Column(String(50), nullable=False)  # request|response|comparison|header|tool_output|certificate|authorization_difference
    request_json = Column(JSON, nullable=True)
    response_json = Column(JSON, nullable=True)
    expected = Column(Text, nullable=True)
    actual = Column(Text, nullable=True)
    security_boundary = Column(Text, nullable=True)
    redaction_status = Column(String(50), default="redacted")
    # Phase 6 evidence integrity: hashes over the redacted payload so accidental
    # mutation is detectable; bounded body capture metadata.
    request_hash = Column(String(64), nullable=True)
    response_hash = Column(String(64), nullable=True)
    original_size = Column(Integer, nullable=True)  # observed response body size (bytes)
    captured_size = Column(Integer, nullable=True)  # bytes actually persisted
    truncated = Column(Boolean, nullable=True)  # True when the body was bounded
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Vulnerability", back_populates="evidence_records")
    observation = relationship("Observation")


class FindingStatusHistory(Base):
    """Immutable audit trail of a finding's lifecycle transitions.

    Every status change (candidate -> confirmed -> remediated -> reopened, or any
    manual triage transition) appends a row here.  Historical state is never
    overwritten or deleted.
    """
    __tablename__ = "finding_status_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    from_status = Column(String(50), nullable=False)
    to_status = Column(String(50), nullable=False)
    actor = Column(String(255), nullable=False, default="system")
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    finding = relationship("Vulnerability", back_populates="status_history")


class ReportExport(Base):
    """Persisted, reproducibility metadata for a generated assessment report.

    The report body is regenerated deterministically from persisted state; this
    row records what was generated, when, and against which assessment version
    (registry + configuration fingerprints) so the report is reproducible.
    """
    __tablename__ = "report_exports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    user_id = Column(String(255), nullable=True)
    format = Column(String(20), nullable=False)  # json|markdown
    content_hash = Column(String(64), nullable=True)  # SHA-256 of the rendered payload
    registry_fingerprint = Column(String(64), nullable=True)
    config_fingerprint = Column(String(64), nullable=True)
    content_length = Column(Integer, nullable=True)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    content_json = Column(JSON, nullable=True)
    content_markdown = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="report_exports")
