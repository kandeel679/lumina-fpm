"""SQLAlchemy ORM models for the Lumina Threat Intel module.

Tables:
  - threat_intel_reports       — one row per scan invocation
  - threat_intel_findings      — individual findings within a report
  - threat_intel_iocs          — IOCs extracted from findings
  - threat_intel_raw_scrapes   — temporary raw scraped content (7-day retention)

All tables use Integer autoincrement PKs to match the existing Lumina convention.
No tenant_id columns — the project is single-tenant for graduation scope.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

# Import the shared Base from the existing models module
from models.models import Base


class ThreatIntelReport(Base):
    __tablename__ = "threat_intel_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    trigger_type = Column(
        Enum("scheduled", "manual", "on_import", name="ti_trigger_type"),
        nullable=False,
    )
    triggered_by_admin_id = Column(
        Integer,
        ForeignKey("administrator.admin_id"),
        nullable=True,
    )
    status = Column(
        Enum("running", "completed", "failed", "partial", name="ti_scan_status"),
        nullable=False,
        default="running",
    )
    scan_started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    scan_completed_at = Column(DateTime, nullable=True)
    scan_duration_seconds = Column(Integer, nullable=True)

    # Snapshot of the keyword bundle used for this scan
    input_keywords = Column(JSONB, nullable=True)

    queries_generated_count = Column(Integer, nullable=True)
    onion_pages_scraped_count = Column(Integer, nullable=True)

    # Markdown narrative produced by the final LLM call
    narrative_summary = Column(Text, nullable=True)

    # Aggregated stats: {total, by_severity, by_category}
    stats = Column(JSONB, nullable=True)

    # LLM usage tracking
    llm_model_name = Column(String(128), nullable=True)
    llm_input_tokens = Column(Integer, nullable=True)
    llm_output_tokens = Column(Integer, nullable=True)

    # List of {stage, error_msg, ts} dicts
    error_log = Column(JSONB, nullable=True)

    archived = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    findings = relationship(
        "ThreatIntelFinding",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    raw_scrapes = relationship(
        "ThreatIntelRawScrape",
        back_populates="report",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_ti_report_started", "scan_started_at"),
        Index("idx_ti_report_archived", "archived", "scan_started_at"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelReport(id={self.id}, status='{self.status}')>"


class ThreatIntelFinding(Base):
    __tablename__ = "threat_intel_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(
        Integer,
        ForeignKey("threat_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    category = Column(
        Enum("exploit", "credential", "c2", "ransomware", "iab", name="ti_category"),
        nullable=False,
    )
    severity = Column(
        Enum("critical", "high", "medium", "low", name="ti_severity"),
        nullable=False,
    )
    confidence = Column(Integer, nullable=False, default=50)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    # List of free-text action strings
    recommended_actions = Column(JSONB, nullable=True)
    # List of tag strings
    tags = Column(JSONB, nullable=True)

    # Source provenance
    source_onion_url = Column(Text, nullable=True)
    source_search_engine = Column(String(128), nullable=True)
    source_scraped_at = Column(DateTime, nullable=True)
    source_raw_excerpt = Column(Text, nullable=True)  # max ~500 chars
    source_page_title = Column(String(512), nullable=True)
    source_marketplace_or_forum = Column(String(256), nullable=True)

    # Correlation results (populated by correlator)
    matched_rule_ids = Column(JSONB, nullable=True)    # list[int]
    matched_device_ids = Column(JSONB, nullable=True)  # list[int]
    correlation_match_reason = Column(Text, nullable=True)

    # Diff tracking
    is_new_since_last_scan = Column(Boolean, nullable=True)
    first_seen_in_scan_id = Column(
        Integer,
        ForeignKey("threat_intel_reports.id"),
        nullable=True,
    )
    # SHA256(category|title|sorted_iocs) — for dedup / diff detection
    finding_hash = Column(String(64), nullable=True, index=True)

    parse_error = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    report = relationship("ThreatIntelReport", back_populates="findings",
                          foreign_keys=[report_id])
    iocs = relationship(
        "ThreatIntelIOC",
        back_populates="finding",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_ti_finding_severity", "severity", "created_at"),
        Index("idx_ti_finding_report", "report_id"),
        Index("idx_ti_finding_hash", "finding_hash"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelFinding(id={self.id}, title='{self.title[:40]}')>"


class ThreatIntelIOC(Base):
    __tablename__ = "threat_intel_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(
        Integer,
        ForeignKey("threat_intel_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    ioc_type = Column(
        Enum(
            "ipv4", "ipv6", "domain", "url", "sha256", "md5", "sha1",
            "cve", "email", "wallet", "username", "asn",
            name="ti_ioc_type",
        ),
        nullable=False,
    )
    ioc_value = Column(String(2048), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding = relationship("ThreatIntelFinding", back_populates="iocs")

    __table_args__ = (
        Index("idx_ti_ioc_type_value", "ioc_type", "ioc_value"),
        Index("idx_ti_ioc_finding", "finding_id"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelIOC(id={self.id}, type='{self.ioc_type}', value='{self.ioc_value[:40]}')>"


class ThreatIntelRawScrape(Base):
    """Temporary storage for raw scraped dark-web content.
    Auto-purged after 7 days by the retention job.
    """
    __tablename__ = "threat_intel_raw_scrapes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(
        Integer,
        ForeignKey("threat_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    onion_url = Column(Text, nullable=True)
    search_engine = Column(String(128), nullable=True)
    scraped_at = Column(DateTime, nullable=True)
    http_status = Column(Integer, nullable=True)
    content_length = Column(Integer, nullable=True)
    raw_text = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    report = relationship("ThreatIntelReport", back_populates="raw_scrapes")

    __table_args__ = (
        Index("idx_ti_raw_scrape_date", "scraped_at"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelRawScrape(id={self.id}, url='{(self.onion_url or '')[:40]}')>"
