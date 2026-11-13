"""
database/db.py
SQLAlchemy engine + session factory.

Connection string is read from the DATABASE_URL environment variable.
Default: SQLite file at database/scans.db

To switch to PostgreSQL later, just change DATABASE_URL:
    DATABASE_URL=postgresql://user:pass@localhost/security_analyzer
"""
import os
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# ── Connection string ────────────────────────────────────────
# Default: SQLite in the database/ folder next to this file
_default_sqlite = "sqlite:///" + str(
    Path(__file__).parent / "scans.db"
)
DATABASE_URL = os.environ.get("DATABASE_URL", _default_sqlite)

# ── Engine ───────────────────────────────────────────────────
# connect_args only needed for SQLite (allows use in multi-threaded Flask)
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args, echo=False)

# ── Session factory ──────────────────────────────────────────
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


# ── Base class for all ORM models ────────────────────────────
class Base(DeclarativeBase):
    pass


def get_db():
    """Yield a DB session and close it when done (use as context manager)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables if they do not yet exist.
    For SQLite, also apply lightweight schema migrations (ALTER TABLE ADD COLUMN)
    so older `scans.db` files keep working across sprints.
    """
    # Import models so their metadata is registered on Base
    import database.models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    if DATABASE_URL.startswith("sqlite"):
        _sqlite_migrate()


def _sqlite_has_column(table: str, col: str) -> bool:
    with engine.connect() as conn:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == col for r in rows)  # type: ignore[index]


def _sqlite_migrate() -> None:
    with engine.begin() as conn:
        # scans: risk_score, risk_level
        if not _sqlite_has_column("scans", "risk_score"):
            conn.execute(text("ALTER TABLE scans ADD COLUMN risk_score INTEGER"))
        if not _sqlite_has_column("scans", "risk_level"):
            conn.execute(text("ALTER TABLE scans ADD COLUMN risk_level VARCHAR(16)"))
        # vulnerabilities: phase-1 metadata columns
        if not _sqlite_has_column("vulnerabilities", "fingerprint"):
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN fingerprint VARCHAR(64)"))
        if not _sqlite_has_column("vulnerabilities", "analyzer"):
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN analyzer VARCHAR(64)"))
        if not _sqlite_has_column("vulnerabilities", "rule_id"):
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN rule_id VARCHAR(128)"))
        if not _sqlite_has_column("vulnerabilities", "confidence"):
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN confidence VARCHAR(16)"))
        # scan_jobs: phase 1 codeql toggle
        if not _sqlite_has_column("scan_jobs", "codeql_enabled"):
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN codeql_enabled BOOLEAN NOT NULL DEFAULT 0"))
        if not _sqlite_has_column("scan_jobs", "analysis_modules_json"):
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN analysis_modules_json TEXT"))
        if not _sqlite_has_column("scan_jobs", "semgrep_profile"):
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN semgrep_profile VARCHAR(32)"))
        # scan_telemetry: phase 1 codeql counters
        if not _sqlite_has_column("scan_telemetry", "codeql_enabled"):
            conn.execute(text("ALTER TABLE scan_telemetry ADD COLUMN codeql_enabled BOOLEAN NOT NULL DEFAULT 0"))
        if not _sqlite_has_column("scan_telemetry", "codeql_finding_count"):
            conn.execute(text("ALTER TABLE scan_telemetry ADD COLUMN codeql_finding_count INTEGER NOT NULL DEFAULT 0"))
