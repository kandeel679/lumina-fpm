/**
 * Typed API client for LuminaFPM (Phase 10).
 *
 * Single source of truth for talking to the FastAPI backend. Every new TSX
 * screen imports from here instead of hand-rolling `fetch` calls, so request
 * shapes and response types stay in lock-step with the backend routes.
 *
 * The legacy aggregate loader (`src/api.js`, consumed by LFPMContext) stays as
 * is for now; new endpoints (risk, benchmark, cti, reports, anomalies) are typed
 * here and migrated screen-by-screen.
 *
 * Read-only platform: nothing here writes to a firewall. POST endpoints only
 * trigger LuminaFPM's own analysis jobs (anomaly/risk/cti/benchmark/report).
 */

/* ─────────────────────────── shared severity / tiers ─────────────────────── */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskTier = 'critical' | 'high' | 'medium' | 'low' | 'minimal';
export type DetectionMode = 'config_only' | 'conditional' | 'simulated' | 'cti' | 'future_enhanced';
export type AnomalyStatus =
  | 'open' | 'resolved' | 'suppressed' | 'accepted_risk' | 'false_positive';

/* ───────────────────────────── HTTP plumbing ────────────────────────────── */

export class ApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string) {
    super(`API ${status}: ${body.slice(0, 200)}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

const BASE = '/api/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    throw new ApiError(res.status, await res.text().catch(() => ''));
  }
  // 204 / empty bodies → null
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });

/* ─────────────────────────── core inventory types ───────────────────────── */

export interface Vendor {
  vendor_id: number;
  name: string;
}

export interface Device {
  device_id: number;
  vendor_id: number;
  vendor_type: string;
  hostname: string;
  firmware_version: string | null;
  management_ip: string;
  status: string;
  last_poll_time: string | null;
}

export interface Rule {
  rule_id: number;
  device_id: number;
  rule_name: string;
  vendor_type: string;
  src_zone_interface: string | null;
  dst_zone_interface: string | null;
  security_profile_group: string | null;
  action: string;
  rule_order: number;
  is_active: boolean;
}

export interface NetworkObject {
  object_id: number;
  name: string;
  value: string;
  type: string;
}

export interface RuleObjectMapping {
  object_id: number;
  direction: 'source' | 'destination' | string;
}

/* ───────────────────────────────── anomalies ────────────────────────────── */

export interface Anomaly {
  anomaly_id: number;
  rule_id: number;
  related_rule_id: number | null;
  anomaly_type: string;
  severity_level: Severity;
  confidence: number | null;
  description: string | null;
  evidence: Record<string, unknown> | null;
  recommendation: string | null;
  detection_mode: DetectionMode | string;
  analysis_run_id: number | null;
  status: AnomalyStatus | string;
  detected_at: string | null;
  // present when the row was joined to its policy_rule
  device_id?: number;
  rule_name?: string;
  vendor_type?: string;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface AnomalyRun {
  run_id: number;
  scope_type: string;
  scope_id: number | null;
  status: string;
  findings_count: number | null;
  started_at: string | null;
  completed_at: string | null;
  engine_version: string | null;
}

export interface AnomalyFilters {
  severity?: Severity;
  anomaly_type?: string;
  status?: AnomalyStatus;
  device_id?: number;
  analysis_run_id?: number;
  page?: number;
  page_size?: number;
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export const anomalies = {
  list: (f: AnomalyFilters = {}) => get<Paged<Anomaly>>(`/anomalies${qs(f as Record<string, unknown>)}`),
  get: (id: number) => get<Anomaly>(`/anomalies/${id}`),
  runs: (limit = 20) => get<{ items: AnomalyRun[] }>(`/anomalies/runs${qs({ limit })}`),
  run: (device_id?: number) =>
    post<{ status: string; task_id: string; scope: string; device_id: number | null }>(
      '/anomalies/run', { device_id: device_id ?? null }),
  updateStatus: (id: number, body: { status: AnomalyStatus; reason?: string; admin_id?: number }) =>
    patch<Anomaly>(`/anomalies/${id}`, body),
};

/* ─────────────────────────────────── risk ───────────────────────────────── */

export interface RiskFactorBreakdown {
  // V8 factors; all optional — only contributing factors are present.
  anomaly?: number;
  exposure?: number;
  asset_sensitivity?: number;
  security_posture?: number;
  logging?: number;
  cross_vendor?: number;
  cti?: number;
  lifecycle?: number;
  // device-scope modifiers (present on scope_type === 'device')
  firmware_modifier?: number;   // confirmed firmware-CVE contribution (V8 §8)
  [factor: string]: number | undefined;
}

export interface RiskItem {
  scope_type: 'rule' | 'device';
  scope_id: number;
  risk_score: number;
  risk_tier: RiskTier | string;
  factor_breakdown: RiskFactorBreakdown | null;
  calculation_version: string;
  // present for scope_type === 'rule'
  rule_name?: string;
  vendor_type?: string;
  device_id?: number;
}

export interface RiskList {
  analysis_run_id: number | null;
  scope_type?: 'rule' | 'device';
  items: RiskItem[];
}

export const risk = {
  list: (scope_type: 'rule' | 'device' = 'rule', limit = 20) =>
    get<RiskList>(`/risk${qs({ scope_type, limit })}`),
  run: (analysis_run_id?: number) =>
    post<Record<string, unknown>>('/risk/run', { analysis_run_id: analysis_run_id ?? null }),
};

/* ───────────────────────────────── benchmark ────────────────────────────── */

export interface BenchmarkCase {
  anomaly_type: string;
  case_type: string;
  expected_severity: Severity;
  detected: boolean;
  match_quality: string;        // exact | partial | none
  rule_a_id: number | null;
  rule_b_id: number | null;
}

export interface BenchmarkReport {
  analysis_run_id?: number;
  expected_cases?: number;
  detected?: number;
  missed?: number;
  recall?: number;
  severity_match_rate?: number;
  cases?: BenchmarkCase[] | number;   // number (0) when no benchmark has run
  detail?: string;
}

export interface BenchmarkMetrics {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  severity_match_rate: number;
  expected_cases: number;
}

export interface BenchmarkRunResult {
  analysis_run_id: number;
  metrics: BenchmarkMetrics;
  by_type: Record<string, { expected: number; detected: number }>;
}

export const benchmark = {
  report: () => get<BenchmarkReport>('/benchmark/report'),
  run: (analysis_run_id?: number) =>
    post<BenchmarkRunResult>('/benchmark/run', { analysis_run_id: analysis_run_id ?? null }),
};

/* ──────────────────────────────────── cti ───────────────────────────────── */

export interface CtiObservation {
  provider: string;
  severity: Severity | string;
  confidence: number | null;
  threat_type: string | null;
  summary: string | null;
  reference: string | null;
  observed_at: string | null;
}

export interface CtiIndicator {
  indicator_id: number;
  type: string;                 // ip_address | cidr | domain ...
  value: string;
  is_public: boolean;
  source_device_id: number | null;
  malicious: boolean;
  observations: CtiObservation[];
}

export interface CtiRunResult {
  analysis_run_id: number;
  providers: string[];
  indicators_enriched: number;
  malicious_indicators: number;
  threat_exposure_findings: number;
  internal_indicators_sent: boolean;
}

// Device-axis firmware-CVE run summary (services/cti/vuln_runner.run_vuln).
export interface VulnRunResult {
  provider: string;             // 'offline' (v1) | 'live' (v2)
  analysis_run_id: number | null;
  devices_scanned: number;
  devices_vulnerable: number;
  cve_observations: number;
  vendors: string[];
}

// POST /cti/run runs both axes: CTI (rule) + VULN (device).
export interface CtiRunResponse {
  cti: CtiRunResult;
  vuln: VulnRunResult;
}

export const cti = {
  list: () => get<{ indicators: CtiIndicator[]; count: number }>('/cti'),
  run: (analysis_run_id?: number) =>
    post<CtiRunResponse>('/cti/run', { analysis_run_id: analysis_run_id ?? null }),
};

/* ─────────────────────────────────── reports ────────────────────────────── */

export type ReportScope = 'rule' | 'executive';

export interface ReportSummary {
  report_id: number;
  scope_type: ReportScope | string;
  scope_id: number | null;
  provider: string;
  model: string;
  status: string;               // complete | partial | failed
  prompt_version: string;
  evidence_refs: Record<string, unknown> | null;
  confidence_note: string | null;
  created_at: string | null;
}

// ── Structured SOC report document (deterministic sections; V10 §8) ──
export interface SocFinding {
  anomaly_id: number; anomaly_type: string; severity: string;
  detection_mode: string | null; confidence: number | null;
  description: string | null; recommendation: string | null; related_rule: string | null;
}
export interface SocRemediation {
  priority: number; pol: string; rule_name: string; vendor_type: string | null;
  device: string; anomaly_types: string[]; max_severity: string;
  risk_score: number; risk_tier: string; recommendation: string;
}
export interface SocEvidence {
  pol: string; rule_name: string; vendor_type: string | null; device: string;
  risk_score: number; risk_tier: string;
  factor_breakdown: Record<string, number> | null; findings: SocFinding[];
}
export interface SocDeviceRisk {
  device: string; vendor_type: string | null; firmware: string | null;
  risk_score: number; risk_tier: string; factor_breakdown: Record<string, number> | null;
}
export interface SocFirmwareCve {
  device: string; vendor_type: string | null; firmware: string | null; firmware_modifier: number;
  cves: { reference: string | null; provider: string; severity: string; confidence: number | null; summary: string | null }[];
}
export interface SocRuleSummary {
  pol: string; rule_name: string; device: string; vendor_type: string | null;
  action: string; src_zone: string; dst_zone: string; inspection: string | null;
  enabled: boolean; order: number; risk_score: number; risk_tier: string;
}
export interface SocDocument {
  title: string; scope: string; analysis_run_id: number;
  totals: { open_findings: number; rules_with_findings: number; rules_scored: number; devices: number; tier_counts: Record<string, number> };
  rule_summary?: SocRuleSummary;        // present for per-rule reports only
  remediation: SocRemediation[];
  evidence: SocEvidence[];
  risk_posture: { tier_counts: Record<string, number>; devices: SocDeviceRisk[] };
  firmware_cves: SocFirmwareCve[];
}

export interface ReportDetail extends ReportSummary {
  output: string;
  document?: SocDocument | null;        // present for executive reports
  markdown?: string | null;             // downloadable GFM render
  executive_summary?: string | null;    // AI-authored summary only
}

export const reports = {
  list: (limit = 20) => get<{ reports: ReportSummary[] }>(`/reports${qs({ limit })}`),
  get: (id: number) => get<ReportDetail>(`/reports/${id}`),
  generate: (scope_type: ReportScope, scope_id?: number) =>
    post<ReportDetail>('/reports/generate', { scope_type, scope_id: scope_id ?? null }),
};

/* ─────────────────────────── inventory convenience ──────────────────────── */

export const inventory = {
  vendors: () => get<Vendor[]>('/vendors/'),
  devices: () => get<Device[]>('/devices/'),
  rules: () => get<Rule[]>('/rules/'),
  networkObjects: () => get<NetworkObject[]>('/network-objects/'),
  ruleObjects: (ruleId: number) => get<RuleObjectMapping[]>(`/rules/${ruleId}/objects`),
  ruleAnomalies: (ruleId: number) => get<Anomaly[]>(`/rules/${ruleId}/anomalies`),
  syncDevice: (deviceId: number) => post<unknown>(`/devices/${deviceId}/sync`),
  analyzeDevice: (deviceId: number) => post<unknown>(`/rules/device/${deviceId}/analyze`),
};

export const api = { anomalies, risk, benchmark, cti, reports, inventory };
export default api;
