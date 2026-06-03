"""Pydantic schemas for Lumina Threat Intel — input, output, and API models.

These schemas serve double duty:
1. They validate LLM output (the LLM is forced to produce JSON matching these).
2. They define the API request/response shapes.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    SHA1 = "sha1"
    CVE = "cve"
    EMAIL = "email"
    WALLET = "wallet"
    USERNAME = "username"
    ASN = "asn"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatCategory(str, enum.Enum):
    EXPLOIT = "exploit"
    CREDENTIAL = "credential"
    C2 = "c2"
    RANSOMWARE = "ransomware"
    IAB = "iab"


class TriggerType(str, enum.Enum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    ON_IMPORT = "on_import"


class ScanStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


# ---------------------------------------------------------------------------
# LLM Output Schemas (the LLM is forced to produce these)
# ---------------------------------------------------------------------------

class IOC(BaseModel):
    """A single indicator of compromise extracted from scraped data."""
    type: IOCType
    value: str = Field(max_length=2048)


class FindingSource(BaseModel):
    """Provenance information for a finding."""
    onion_url: Optional[str] = None
    search_engine: Optional[str] = None
    scraped_at: Optional[datetime] = None
    raw_excerpt: str = Field(max_length=500)
    page_title: Optional[str] = None
    marketplace_or_forum: Optional[str] = None


class Finding(BaseModel):
    """A single threat finding produced by a refiner prompt."""
    category: ThreatCategory
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    title: str = Field(max_length=512)
    description: str
    iocs: list[IOC] = Field(default_factory=list)
    source: FindingSource
    recommended_actions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class GeneratedQuery(BaseModel):
    """A single dark-web search query + its threat category."""
    query: str = Field(max_length=120)
    category: ThreatCategory


class QueryGenerationOutput(BaseModel):
    """LLM output from the query-generator prompt."""
    queries: list[GeneratedQuery] = Field(default_factory=list)


class CategoryRefinementOutput(BaseModel):
    """LLM output from a single refiner prompt."""
    category: ThreatCategory
    findings: list[Finding] = Field(default_factory=list)


class ConsolidatedFindingsOutput(BaseModel):
    """LLM output from the single consolidated Findings call.

    Replaces the separate Robin narrative + 5 per-category refiner calls
    (6 LLM calls -> 1). ``narrative_summary`` is firewall-scoped; ``findings``
    spans all requested categories in one pass.
    """
    narrative_summary: str = Field(default="")
    findings: list[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Assessment model (Phase 2.4): Criticality x Relevance
# ---------------------------------------------------------------------------

class Criticality(str, enum.Enum):
    """Intrinsic danger of the threat itself (independent of the customer)."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RelevanceBand(str, enum.Enum):
    """How much the finding pertains to THIS firewall inventory."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AssessedFinding(BaseModel):
    """A finding carrying both assessment axes (criticality + relevance).

    The LLM proposes relevance_score/band/reason; code later verifies it
    against the firewall inventory (hybrid relevance) in the correlator.
    """
    category: ThreatCategory
    criticality: Criticality
    relevance_score: int = Field(ge=0, le=100, default=0)
    relevance_band: RelevanceBand = RelevanceBand.NONE
    relevance_reason: str = ""
    confidence: int = Field(ge=0, le=100, default=50)
    title: str = Field(max_length=512)
    description: str = ""
    iocs: list[IOC] = Field(default_factory=list)
    source: FindingSource
    recommended_actions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AssessedFindingsOutput(BaseModel):
    """LLM output from the consolidated Findings call (assessment-model version).

    ``clean`` = no finding reached relevance band medium+ ("this FW is clean").
    ``coverage_note`` summarises what was searched/ruled out for the clean path.
    """
    clean: bool = False
    coverage_note: str = ""
    narrative_summary: str = ""
    findings: list[AssessedFinding] = Field(default_factory=list)


class ReportNarrative(BaseModel):
    """LLM output for the final narrative summary."""
    narrative_summary: str = Field(
        description="Markdown narrative, 3-5 paragraphs, ~500 words"
    )


# ---------------------------------------------------------------------------
# API Request / Response Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """POST /api/threat-intel/scans request body."""
    trigger_type: TriggerType = TriggerType.MANUAL
    categories: list[ThreatCategory] = Field(
        default_factory=lambda: list(ThreatCategory)
    )
    device_ids: Optional[list[int]] = Field(
        default=None,
        description="Device IDs to scan. null or empty = all devices.",
    )
    force_refresh_keywords: bool = False


class ScanCreatedResponse(BaseModel):
    """Immediate response after triggering a scan."""
    report_id: int
    status: ScanStatus = ScanStatus.RUNNING
    device_ids: Optional[list[int]] = None
    device_count: int = 0


class IOCResponse(BaseModel):
    """Single IOC in API response."""
    id: int
    ioc_type: IOCType
    ioc_value: str


class FindingResponse(BaseModel):
    """Single finding in API response."""
    id: int
    report_id: int
    category: ThreatCategory
    severity: Severity
    criticality: Optional[Criticality] = None
    relevance_score: Optional[int] = None
    relevance_band: Optional[RelevanceBand] = None
    relevance_reason: Optional[str] = None
    confidence: int
    title: str
    description: str
    recommended_actions: list[str]
    tags: list[str]
    source_onion_url: Optional[str]
    source_search_engine: Optional[str]
    source_scraped_at: Optional[datetime]
    source_raw_excerpt: Optional[str]
    source_page_title: Optional[str]
    source_marketplace_or_forum: Optional[str]
    matched_rule_ids: list[int]
    matched_device_ids: list[int]
    correlation_match_reason: Optional[str]
    is_new_since_last_scan: bool
    first_seen_in_scan_id: Optional[int]
    parse_error: bool
    iocs: list[IOCResponse] = Field(default_factory=list)
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class ReportStatsResponse(BaseModel):
    """Stats block embedded inside a report response."""
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    total_iocs: int = 0
    correlated_rules: int = 0


class ReportSummaryResponse(BaseModel):
    """Report in list view (no findings attached)."""
    id: int
    trigger_type: TriggerType
    triggered_by_admin_id: Optional[int]
    status: ScanStatus
    scan_started_at: Optional[datetime]
    scan_completed_at: Optional[datetime]
    scan_duration_seconds: Optional[int]
    queries_generated_count: Optional[int]
    onion_pages_scraped_count: Optional[int]
    narrative_summary: Optional[str]
    clean: Optional[bool] = None
    coverage_note: Optional[str] = None
    stats: Optional[ReportStatsResponse]
    llm_model_name: Optional[str]
    scanned_device_ids: Optional[list[int]] = None
    archived: bool
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class ReportDetailResponse(ReportSummaryResponse):
    """Full report with findings."""
    findings: list[FindingResponse] = Field(default_factory=list)
    error_log: Optional[list[dict]] = None


class DashboardStatsResponse(BaseModel):
    """GET /api/threat-intel/dashboard/stats response."""
    total_scans: int
    last_scan_at: Optional[datetime]
    last_scan_status: Optional[ScanStatus]
    total_findings_last_7d: int
    critical_findings_last_7d: int
    high_findings_last_7d: int
    new_findings_last_scan: int
    top_categories: dict[str, int] = Field(default_factory=dict)
    correlated_rules_count: int


class PaginatedResponse(BaseModel):
    """Generic paginated wrapper."""
    items: list = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20
    total_pages: int = 0
