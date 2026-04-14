import { useAuthStore } from '../stores/auth';

const API_BASE = '/api/dashboard';
const MGMT_BASE = '/api/v1';

// ─── Unauthenticated dashboard types (existing) ───────────────────────────────

export interface DashboardStats {
  total_requests: number;
  violations: number;
  pii_detections: number;
  injection_blocks: number;
  avg_latency_ms: number;
  period: string;
}

export interface Violation {
  interaction_id: string;
  tenant_id: string;
  user_id: string;
  department: string | null;
  created_at: string;
  action: string;
  reason: string | null;
  pii_detected: boolean;
  pii_entity_types: string[];
  pii_risk_level: string | null;
  injection_score: number | null;
  injection_type: string | null;
  response_violated: boolean;
  latency_ms: number | null;
}

export interface ViolationsResponse {
  violations: Violation[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelinePoint {
  hour: string;
  total: number;
  violations: number;
  pii: number;
}

export interface TimelineResponse {
  timeline: TimelinePoint[];
}

// ─── Fetch helpers ─────────────────────────────────────────────────────────────

function getAuthHeaders(): Record<string, string> {
  return {
    Authorization: `Bearer ${useAuthStore.getState().token}`,
    'Content-Type': 'application/json',
  };
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function fetchAuth<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: { ...getAuthHeaders(), ...(options?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    throw new Error(String(body.detail ?? body.error ?? `API error: ${res.status}`));
  }
  return res.json() as Promise<T>;
}

// ─── Unauthenticated endpoints (existing) ─────────────────────────────────────

export function fetchStats(): Promise<DashboardStats> {
  return fetchJson<DashboardStats>(`${API_BASE}/stats`);
}

export function fetchViolations(limit = 50, offset = 0): Promise<ViolationsResponse> {
  return fetchJson<ViolationsResponse>(
    `${API_BASE}/violations?limit=${limit}&offset=${offset}`
  );
}

export function fetchTimeline(hours = 24): Promise<TimelineResponse> {
  return fetchJson<TimelineResponse>(`${API_BASE}/timeline?hours=${hours}`);
}

// --- Playground types ---

export interface PlaygroundResponse {
  interaction_id: string;
  governance: {
    pii: {
      has_pii: boolean;
      risk_level: string;
      entity_types: string[];
      entities: Array<{ text: string; entity_type: string; start: number; end: number; confidence: number }>;
      masked_text: string | null;
    };
    injection: {
      risk_score: number;
      attack_type: string | null;
      is_injection: boolean;
      triggered_rules: Array<{ name: string; pattern: string; weight: number }>;
    };
    policy: {
      action: string;
      reason: string | null;
      triggered_policies: string[];
    };
    compliance: {
      violated: boolean;
      violations: Array<{ rule: string; description: string; severity: string }>;
    } | null;
  };
  llm_response: string | null;
  original_text: string;
  masked_text: string | null;
  timing: {
    pii_ms: number;
    injection_ms: number;
    policy_ms: number;
    llm_ms: number;
    compliance_ms: number;
    total_ms: number;
  };
}

export async function postPlaygroundChat(message: string): Promise<PlaygroundResponse> {
  const res = await fetch(`${API_BASE}/playground/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as Record<string, unknown>;
    throw new Error(String(err.reason ?? err.detail ?? `API error: ${res.status}`));
  }
  return res.json() as Promise<PlaygroundResponse>;
}

// ─── Management API types ──────────────────────────────────────────────────────

export interface User {
  id: string;
  tenant_id: string;
  external_id: string;
  email: string | null;
  department: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface UsersResponse {
  users: User[];
}

export interface Escalation {
  id: string;
  interaction_id: string | null;
  tenant_id: string;
  created_at: string;
  reason: string;
  status: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  notes: string | null;
}

export interface EscalationsResponse {
  escalations: Escalation[];
}

export interface PolicyConfig {
  pii?: Record<string, unknown>;
  injection?: Record<string, unknown>;
  response_compliance?: Record<string, unknown>;
  rate_limits?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface Policy {
  id: string;
  tenant_id: string;
  config: PolicyConfig;
  version: string;
  is_active: boolean;
  created_at: string;
  notes: string | null;
}

export interface PolicyVersionsResponse {
  versions: Policy[];
}

export interface AuditLog {
  interaction_id: string;
  tenant_id: string;
  user_id: string;
  department: string | null;
  created_at: string;
  enforcement_action: string;
  enforcement_reason: string | null;
  pii_detected: boolean;
  pii_entity_types: string[];
  pii_risk_level: string | null;
  injection_score: number | null;
  injection_type: string | null;
  response_violated: boolean | null;
  total_latency_ms: number | null;
}

export interface AuditLogsResponse {
  logs: AuditLog[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditExportResponse {
  tenant_id: string;
  count: number;
  logs: AuditLog[];
}

export interface AuditVerifyResponse {
  verified: boolean;
  interaction_id: string;
  tenant_id: string;
}

export interface StatsOverview {
  tenant_id: string;
  total_requests: number;
  violations: number;
  pii_detections: number;
  injection_blocks: number;
  avg_latency_ms: number;
  period: string;
}

export interface DepartmentStat {
  department: string;
  total: number;
  violations: number;
}

export interface DepartmentsResponse {
  tenant_id: string;
  period: string;
  departments: DepartmentStat[];
}

export interface HourStat {
  hour: number;
  total: number;
}

export interface HoursResponse {
  tenant_id: string;
  period: string;
  hours: HourStat[];
}

export interface ComplianceFinding {
  check: string;
  status: 'pass' | 'fail' | 'warning';
  detail: string;
}

export interface GDPRReport {
  report_type: 'gdpr';
  generated_at: string;
  tenant_id: string;
  period: string;
  total_requests: number;
  total_pii_detections: number;
  pii_redacted: number;
  pii_blocked: number;
  pii_escalated: number;
  data_categories_processed: string[];
  cross_border_transfers: boolean;
  retention_policy: string;
  findings: ComplianceFinding[];
}

export interface EUAIActReport {
  report_type: 'eu-ai-act';
  generated_at: string;
  tenant_id: string;
  system_name: string;
  risk_classification: string;
  injection_detection_enabled: boolean;
  injection_detection_method: string;
  human_oversight_escalations: number;
  pending_escalations: number;
  resolved_escalations: number;
  audit_trail_signed: boolean;
  policy_changes_30d: number;
  findings: ComplianceFinding[];
}

export type ComplianceReport = GDPRReport | EUAIActReport;

export interface TenantUsage {
  tenant_id: string;
  plan: string;
  requests_used: number;
  quota: number;
  reset_date: string | null;
}

// ─── Management API calls ─────────────────────────────────────────────────────

export function fetchUsers(): Promise<UsersResponse> {
  return fetchAuth<UsersResponse>(`${MGMT_BASE}/users`);
}

export function deleteUser(userId: string): Promise<{ message: string; user_id: string }> {
  return fetchAuth(`${MGMT_BASE}/users/${userId}`, { method: 'DELETE' });
}

export function fetchEscalations(status?: string): Promise<EscalationsResponse> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : '';
  return fetchAuth<EscalationsResponse>(`${MGMT_BASE}/escalations${qs}`);
}

export function updateEscalation(
  id: string,
  status: string,
  notes?: string
): Promise<Escalation> {
  return fetchAuth<Escalation>(`${MGMT_BASE}/escalations/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ status, notes }),
  });
}

export function fetchPolicy(): Promise<Policy> {
  return fetchAuth<Policy>(`${MGMT_BASE}/policy`);
}

export function updatePolicy(config: PolicyConfig, notes?: string): Promise<Policy> {
  return fetchAuth<Policy>(`${MGMT_BASE}/policy`, {
    method: 'PUT',
    body: JSON.stringify({ config, notes }),
  });
}

export function fetchPolicyVersions(): Promise<PolicyVersionsResponse> {
  return fetchAuth<PolicyVersionsResponse>(`${MGMT_BASE}/policy/versions`);
}

export interface AuditLogParams {
  limit?: number;
  offset?: number;
  action?: string;
  start?: string;
  end?: string;
}

export function fetchAuditLogs(params: AuditLogParams = {}): Promise<AuditLogsResponse> {
  const qs = new URLSearchParams();
  if (params.limit != null) qs.set('limit', String(params.limit));
  if (params.offset != null) qs.set('offset', String(params.offset));
  if (params.action) qs.set('action', params.action);
  if (params.start) qs.set('start', params.start);
  if (params.end) qs.set('end', params.end);
  const q = qs.toString();
  return fetchAuth<AuditLogsResponse>(`${MGMT_BASE}/audit/logs${q ? `?${q}` : ''}`);
}

export async function exportAuditLogs(format: 'json' | 'csv', limit = 1000): Promise<void> {
  const res = await fetch(
    `${MGMT_BASE}/audit/export?format=${format}&limit=${limit}`,
    { headers: getAuthHeaders() }
  );
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);

  if (format === 'csv') {
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_export.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } else {
    const data = await res.json() as Record<string, unknown>;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_export.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

export function verifyAuditLog(interactionId: string): Promise<AuditVerifyResponse> {
  return fetchAuth<AuditVerifyResponse>(`${MGMT_BASE}/audit/verify/${interactionId}`, {
    method: 'POST',
  });
}

export function fetchStatsOverview(): Promise<StatsOverview> {
  return fetchAuth<StatsOverview>(`${MGMT_BASE}/stats/overview`);
}

export function fetchStatsDepartments(): Promise<DepartmentsResponse> {
  return fetchAuth<DepartmentsResponse>(`${MGMT_BASE}/stats/departments`);
}

export function fetchStatsHours(): Promise<HoursResponse> {
  return fetchAuth<HoursResponse>(`${MGMT_BASE}/stats/hours`);
}

export function fetchComplianceReport(type: 'gdpr' | 'eu-ai-act'): Promise<ComplianceReport> {
  return fetchAuth<ComplianceReport>(`${MGMT_BASE}/reports/${type}`);
}

export function fetchTenantUsage(): Promise<TenantUsage> {
  return fetchAuth<TenantUsage>(`${MGMT_BASE}/tenant/usage`);
}
