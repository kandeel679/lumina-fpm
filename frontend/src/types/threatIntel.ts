/**
 * TypeScript types matching the Pydantic schemas from the backend.
 * These are the canonical type definitions for all Threat Intel data.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ThreatCategory = 'exploit' | 'credential' | 'c2' | 'ransomware' | 'iab';
export type TriggerType = 'scheduled' | 'manual' | 'on_import';
export type ScanStatus = 'running' | 'completed' | 'failed' | 'partial';
export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256' | 'md5' | 'sha1' | 'cve' | 'email' | 'wallet' | 'username' | 'asn';

export interface IOCResponse {
  id: number;
  ioc_type: IOCType;
  ioc_value: string;
}

export interface FindingResponse {
  id: number;
  report_id: number;
  category: ThreatCategory;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  recommended_actions: string[];
  tags: string[];
  source_onion_url: string | null;
  source_search_engine: string | null;
  source_scraped_at: string | null;
  source_raw_excerpt: string | null;
  source_page_title: string | null;
  source_marketplace_or_forum: string | null;
  matched_rule_ids: number[];
  matched_device_ids: number[];
  correlation_match_reason: string | null;
  is_new_since_last_scan: boolean;
  first_seen_in_scan_id: number | null;
  parse_error: boolean;
  iocs: IOCResponse[];
  created_at: string | null;
}

export interface ReportStats {
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_category: Record<ThreatCategory, number>;
  total_iocs: number;
  correlated_rules: number;
}

export interface ReportSummary {
  id: number;
  trigger_type: TriggerType;
  triggered_by_admin_id: number | null;
  status: ScanStatus;
  scan_started_at: string | null;
  scan_completed_at: string | null;
  scan_duration_seconds: number | null;
  queries_generated_count: number | null;
  onion_pages_scraped_count: number | null;
  narrative_summary: string | null;
  stats: ReportStats | null;
  llm_model_name: string | null;
  archived: boolean;
  created_at: string | null;
}

export interface ReportDetail extends ReportSummary {
  findings: FindingResponse[];
  error_log: Array<{ stage: string; error_msg: string; ts: string }> | null;
}

export interface DashboardStats {
  total_scans: number;
  last_scan_at: string | null;
  last_scan_status: ScanStatus | null;
  total_findings_last_7d: number;
  critical_findings_last_7d: number;
  high_findings_last_7d: number;
  new_findings_last_scan: number;
  top_categories: Record<string, number>;
  correlated_rules_count: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ScanCreatedResponse {
  report_id: number;
  status: ScanStatus;
}

export interface RuleFindingsResponse {
  rule_id: number;
  count: number;
  findings: Array<{
    id: number;
    title: string;
    severity: Severity;
    category: ThreatCategory;
    confidence: number;
    report_id: number;
  }>;
}

// SSE event types
export type SSEEventType =
  | 'scan_started'
  | 'keywords_extracted'
  | 'queries_generated'
  | 'scraping_progress'
  | 'category_refined'
  | 'correlation_complete'
  | 'done'
  | 'failed';

export interface SSEEvent {
  event: SSEEventType;
  data: Record<string, unknown>;
  timestamp: number;
}

// Severity color mapping helper
export const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  critical: {
    label: 'CRITICAL',
    color: 'var(--color-severity-critical)',
    bg: 'var(--color-severity-critical-bg)',
    border: 'var(--color-severity-critical-border)',
  },
  high: {
    label: 'HIGH',
    color: 'var(--color-severity-high)',
    bg: 'var(--color-severity-high-bg)',
    border: 'var(--color-severity-high-border)',
  },
  medium: {
    label: 'MEDIUM',
    color: 'var(--color-severity-medium)',
    bg: 'var(--color-severity-medium-bg)',
    border: 'var(--color-severity-medium-border)',
  },
  low: {
    label: 'LOW',
    color: 'var(--color-severity-low)',
    bg: 'var(--color-severity-low-bg)',
    border: 'var(--color-severity-low-border)',
  },
};

export const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  exploit: 'Exploits & 0-Days',
  credential: 'Leaked Credentials',
  c2: 'C2 Infrastructure',
  ransomware: 'Ransomware',
  iab: 'Initial Access Brokers',
};
