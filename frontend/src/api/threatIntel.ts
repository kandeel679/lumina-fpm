/**
 * API client for /api/threat-intel endpoints.
 * All functions return typed responses.
 */
import type {
  DashboardStats,
  FindingResponse,
  PaginatedResponse,
  ReportDetail,
  ReportSummary,
  RuleFindingsResponse,
  ScanCreatedResponse,
  ThreatCategory,
} from '../types/threatIntel';

const API_BASE = '/api/threat-intel';

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `API error: ${res.status}`);
  }
  return res.json();
}

/** Trigger a manual scan */
export function triggerScan(categories?: ThreatCategory[]): Promise<ScanCreatedResponse> {
  return apiFetch('/scans', {
    method: 'POST',
    body: JSON.stringify({
      trigger_type: 'manual',
      categories: categories || ['exploit', 'credential', 'c2', 'ransomware', 'iab'],
      force_refresh_keywords: false,
    }),
  });
}

/** List reports (paginated) */
export function listReports(
  page = 1,
  pageSize = 20,
  archived = false,
): Promise<PaginatedResponse<ReportSummary>> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    archived: String(archived),
  });
  return apiFetch(`/scans?${params}`);
}

/** Get a single report with all findings */
export function getReportDetail(reportId: number): Promise<ReportDetail> {
  return apiFetch(`/scans/${reportId}`);
}

/** Archive (soft-delete) a report */
export function archiveReport(reportId: number): Promise<{ message: string }> {
  return apiFetch(`/scans/${reportId}`, { method: 'DELETE' });
}

/** List findings across all reports (with filters) */
export function listFindings(params: {
  page?: number;
  page_size?: number;
  severity?: string;
  category?: string;
  correlated_only?: boolean;
  new_only?: boolean;
  search?: string;
}): Promise<PaginatedResponse<FindingResponse>> {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') search.set(k, String(v));
  });
  return apiFetch(`/findings?${search}`);
}

/** Get a single finding */
export function getFinding(findingId: number): Promise<FindingResponse> {
  return apiFetch(`/findings/${findingId}`);
}

/** Dashboard overview stats */
export function getDashboardStats(): Promise<DashboardStats> {
  return apiFetch('/dashboard/stats');
}

/** Findings correlated to a specific firewall rule */
export function getRuleFindings(ruleId: number): Promise<RuleFindingsResponse> {
  return apiFetch(`/rules/${ruleId}/findings`);
}

/** Create an SSE EventSource for scan progress */
export function createScanStream(reportId: number): EventSource {
  return new EventSource(`${API_BASE}/scans/${reportId}/stream`);
}
