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
  severity: 'info' | 'warning' | 'critical';
  reviewed_by: string | null;
  reviewed_at: string | null;
  notes: string | null;
  assignee_user_id: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_notes: string | null;
  sla_breached: boolean;
  sla_target_minutes: number;
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
  requests_today: number;
  requests_this_month: number;
  blocked_today: number;
  pii_detections_today: number;
  injection_detections_today: number;
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

export function acknowledgeEscalation(id: string, notes?: string): Promise<Escalation> {
  return fetchAuth<Escalation>(`${MGMT_BASE}/escalations/${id}/acknowledge`, {
    method: 'POST',
    body: JSON.stringify({ notes }),
  });
}

export function assignEscalation(id: string, assignee_user_id: string | null): Promise<Escalation> {
  return fetchAuth<Escalation>(`${MGMT_BASE}/escalations/${id}/assign`, {
    method: 'POST',
    body: JSON.stringify({ assignee_user_id }),
  });
}

export function resolveEscalation(id: string, resolution_notes: string): Promise<Escalation> {
  return fetchAuth<Escalation>(`${MGMT_BASE}/escalations/${id}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ resolution_notes }),
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

// ─── SSO ──────────────────────────────────────────────────────────────────────

export interface SSOStatus {
  configured: boolean;
}

export interface TenantSSOConfig {
  workos_org_id: string | null;
  sso_enforced: boolean;
}

export function fetchSSOStatus(): Promise<SSOStatus> {
  return fetchJson<SSOStatus>(`${MGMT_BASE}/auth/sso/status`);
}

export function fetchTenantSSO(): Promise<TenantSSOConfig> {
  return fetchAuth<TenantSSOConfig>(`${MGMT_BASE}/tenant/sso`);
}

export function updateTenantSSO(
  body: { workos_org_id?: string | null; sso_enforced?: boolean }
): Promise<{ message: string; sso: TenantSSOConfig }> {
  return fetchAuth<{ message: string; sso: TenantSSOConfig }>(
    `${MGMT_BASE}/tenant/sso`,
    { method: 'PUT', body: JSON.stringify(body) }
  );
}

// ─── MFA ──────────────────────────────────────────────────────────────────────

export interface MFAStatus {
  enrolled: boolean;
  enabled: boolean;
}

export interface MFAEnrollResponse {
  provisioning_uri: string;
  qr_png_data_url: string;
  recovery_codes: string[];
}

export function fetchMFAStatus(): Promise<MFAStatus> {
  return fetchAuth<MFAStatus>(`${MGMT_BASE}/auth/mfa/status`);
}

export function startMFAEnrollment(): Promise<MFAEnrollResponse> {
  return fetchAuth<MFAEnrollResponse>(`${MGMT_BASE}/auth/mfa/enroll`, {
    method: 'POST',
  });
}

export function verifyMFAEnrollment(code: string): Promise<{ message: string }> {
  return fetchAuth<{ message: string }>(`${MGMT_BASE}/auth/mfa/verify-enrollment`, {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export function disableMFA(): Promise<{ message: string }> {
  return fetchAuth<{ message: string }>(`${MGMT_BASE}/auth/mfa/disable`, {
    method: 'POST',
  });
}

// ─── Sessions (Phase 6.5) ─────────────────────────────────────────────────────

export interface AuthSession {
  jti: string;
  issued_at: string;
  expires_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  user_agent: string | null;
  ip_address: string | null;
  issued_via: 'api_key' | 'sso' | 'mfa' | 'refresh';
  current: boolean;
}

export function fetchMySessions(): Promise<{ sessions: AuthSession[] }> {
  return fetchAuth<{ sessions: AuthSession[] }>(`${MGMT_BASE}/auth/sessions`);
}

export function revokeSession(jti: string): Promise<{ revoked: boolean; jti: string }> {
  return fetchAuth<{ revoked: boolean; jti: string }>(
    `${MGMT_BASE}/auth/sessions/${encodeURIComponent(jti)}`,
    { method: 'DELETE' }
  );
}

export function revokeAllSessions(): Promise<{ revoked_count: number }> {
  return fetchAuth<{ revoked_count: number }>(
    `${MGMT_BASE}/auth/sessions/revoke-all`,
    { method: 'POST' }
  );
}

// ─── GDPR Art. 17 purge (Phase 6.6) ────────────────────────────────────────────

export type PurgeRequestState =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'executed';

export interface PurgeRequest {
  id: string;
  tenant_id: string;
  subject_user_id: string;
  subject_tenant_user_id: string | null;
  requested_by: string;
  requested_at: string;
  approval_expires_at: string;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  executed_at: string | null;
  rows_redacted: number | null;
  state: PurgeRequestState;
  reason: string;
}

export function fetchPurgeRequests(): Promise<{ requests: PurgeRequest[] }> {
  return fetchAuth<{ requests: PurgeRequest[] }>(`${MGMT_BASE}/gdpr/purge-requests`);
}

export function createPurgeRequest(
  subject_user_id: string,
  reason: string
): Promise<PurgeRequest> {
  return fetchAuth<PurgeRequest>(`${MGMT_BASE}/gdpr/purge-requests`, {
    method: 'POST',
    body: JSON.stringify({ subject_user_id, reason }),
  });
}

export function approvePurgeRequest(id: string): Promise<PurgeRequest> {
  return fetchAuth<PurgeRequest>(
    `${MGMT_BASE}/gdpr/purge-requests/${encodeURIComponent(id)}/approve`,
    { method: 'POST', body: JSON.stringify({}) }
  );
}

export function rejectPurgeRequest(id: string): Promise<PurgeRequest> {
  return fetchAuth<PurgeRequest>(
    `${MGMT_BASE}/gdpr/purge-requests/${encodeURIComponent(id)}/reject`,
    { method: 'POST', body: JSON.stringify({}) }
  );
}

export function executePurgeRequest(
  id: string
): Promise<PurgeRequest & { redaction_record_ids: string[] }> {
  return fetchAuth<PurgeRequest & { redaction_record_ids: string[] }>(
    `${MGMT_BASE}/gdpr/purge-requests/${encodeURIComponent(id)}/execute`,
    { method: 'POST' }
  );
}

// ─── Phase 7.1: Onboarding wizard ─────────────────────────────────────────────

export interface OnboardingCatalog {
  industries: string[];
  company_sizes: string[];
  regions: string[];
  frameworks: {
    id: string;
    label: string;
    suggested_pack: string;
    citation_root: string;
  }[];
}

export interface OnboardingState {
  tenant_profile?: { industry: string; company_size: string; region: string };
  frameworks?: string[];
  suggested_packs?: string[];
  policy_packs?: string[];
  first_call?: { interaction_id: string };
  completed?: boolean;
}

export function fetchOnboardingCatalog(): Promise<OnboardingCatalog> {
  return fetchJson<OnboardingCatalog>(`${MGMT_BASE}/onboarding/catalog`);
}

export function fetchOnboardingState(): Promise<{
  state: OnboardingState;
  completed: boolean;
}> {
  return fetchAuth<{ state: OnboardingState; completed: boolean }>(
    `${MGMT_BASE}/onboarding/state`
  );
}

export function submitTenantProfile(profile: {
  industry: string;
  company_size: string;
  region: string;
}): Promise<{ state: OnboardingState }> {
  return fetchAuth<{ state: OnboardingState }>(
    `${MGMT_BASE}/onboarding/tenant-profile`,
    { method: 'POST', body: JSON.stringify(profile) }
  );
}

export function submitFrameworks(
  selected: string[]
): Promise<{ state: OnboardingState; suggested_packs: string[] }> {
  return fetchAuth<{ state: OnboardingState; suggested_packs: string[] }>(
    `${MGMT_BASE}/onboarding/frameworks`,
    { method: 'POST', body: JSON.stringify({ selected }) }
  );
}

export function submitPolicyPacks(
  packs: string[]
): Promise<{ state: OnboardingState }> {
  return fetchAuth<{ state: OnboardingState }>(
    `${MGMT_BASE}/onboarding/policy-packs`,
    { method: 'POST', body: JSON.stringify({ packs }) }
  );
}

export function recordFirstCall(
  interactionId: string
): Promise<{ state: OnboardingState }> {
  return fetchAuth<{ state: OnboardingState }>(
    `${MGMT_BASE}/onboarding/first-call`,
    { method: 'POST', body: JSON.stringify({ interaction_id: interactionId }) }
  );
}

export function resetOnboarding(): Promise<{ state: OnboardingState }> {
  return fetchAuth<{ state: OnboardingState }>(
    `${MGMT_BASE}/onboarding/reset`,
    { method: 'POST' }
  );
}

// ─── Policy packs ────────────────────────────────────────────────────────────

export interface PolicyPackSummary {
  id: string;
  name: string;
  framework: string;
  version: string;
  description: string;
  rule_count: number;
  citations: string[];
}

export interface PolicyPackRule {
  id: string;
  description: string;
  action: string;
  when?: Record<string, unknown>;
  framework_citations?: string[];
}

export interface PolicyPack {
  id: string;
  name: string;
  framework: string;
  version: string;
  description?: string;
  metadata?: { framework_citations?: { id: string; title: string; url: string }[] };
  overrides?: Record<string, unknown>;
  rules?: PolicyPackRule[];
}

export function fetchPolicyPacks(): Promise<{ packs: PolicyPackSummary[] }> {
  return fetchAuth<{ packs: PolicyPackSummary[] }>(`${MGMT_BASE}/policy/packs`);
}

export function fetchPolicyPack(packId: string): Promise<PolicyPack> {
  return fetchAuth<PolicyPack>(`${MGMT_BASE}/policy/packs/${packId}`);
}

// ─── Demo / sample data toggle (Settings → Advanced) ────────────────────────

export interface DemoStatus {
  demo_mode_enabled: boolean;
  demo_audit_rows: number;
}

export interface DemoSeedResult {
  seeded: { users: number; audit_rows: number; escalations: number };
  demo_mode_enabled: boolean;
}

export interface DemoClearResult {
  cleared: { users: number; audit_rows: number; escalations: number };
  demo_mode_enabled: boolean;
}

export function fetchDemoStatus(): Promise<DemoStatus> {
  return fetchAuth<DemoStatus>(`${MGMT_BASE}/demo/status`);
}

export function seedDemoData(): Promise<DemoSeedResult> {
  return fetchAuth<DemoSeedResult>(`${MGMT_BASE}/demo/seed`, { method: 'POST' });
}

export function clearDemoData(): Promise<DemoClearResult> {
  return fetchAuth<DemoClearResult>(`${MGMT_BASE}/demo/clear`, { method: 'POST' });
}

// ─── Notification providers + rules (Settings → Integrations) ───────────────

export type ProviderKind = 'slack' | 'pagerduty' | 'webhook' | 'email' | 'splunk_hec';
export type TriggerEvent =
  | 'violation'
  | 'escalation'
  | 'audit_chain_break'
  | 'rate_limit_breach';
export type Severity = 'info' | 'warning' | 'critical';

export interface NotificationProvider {
  id: string;
  kind: ProviderKind;
  name: string;
  enabled: boolean;
  created_at: string;
  config?: Record<string, unknown>;
}

export interface NotificationRule {
  id: string;
  provider_id: string;
  provider_name?: string;
  provider_kind?: ProviderKind;
  trigger_event: TriggerEvent;
  severity_min: Severity;
  enabled: boolean;
  created_at: string;
}

export interface NotificationDelivery {
  id: string;
  rule_id: string | null;
  provider_kind: ProviderKind;
  trigger_event: TriggerEvent;
  severity: Severity;
  status: 'sent' | 'failed' | 'retrying';
  attempts: number;
  error: string | null;
  created_at: string;
}

export function fetchNotificationProviders(): Promise<{ providers: NotificationProvider[] }> {
  return fetchAuth<{ providers: NotificationProvider[] }>(`${MGMT_BASE}/notifications/providers`);
}

export function createNotificationProvider(body: {
  kind: ProviderKind;
  name: string;
  config: Record<string, unknown>;
  enabled?: boolean;
}): Promise<NotificationProvider> {
  return fetchAuth<NotificationProvider>(`${MGMT_BASE}/notifications/providers`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function deleteNotificationProvider(id: string): Promise<{ deleted: boolean }> {
  return fetchAuth<{ deleted: boolean }>(`${MGMT_BASE}/notifications/providers/${id}`, {
    method: 'DELETE',
  });
}

export function testNotificationProvider(id: string): Promise<{
  status: string;
  attempts: number;
  error?: string | null;
}> {
  return fetchAuth(`${MGMT_BASE}/notifications/providers/${id}/test`, { method: 'POST' });
}

export function fetchNotificationRules(): Promise<{ rules: NotificationRule[] }> {
  return fetchAuth<{ rules: NotificationRule[] }>(`${MGMT_BASE}/notifications/rules`);
}

export function createNotificationRule(body: {
  provider_id: string;
  trigger_event: TriggerEvent;
  severity_min: Severity;
  enabled?: boolean;
}): Promise<NotificationRule> {
  return fetchAuth<NotificationRule>(`${MGMT_BASE}/notifications/rules`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function deleteNotificationRule(id: string): Promise<{ deleted: boolean }> {
  return fetchAuth<{ deleted: boolean }>(`${MGMT_BASE}/notifications/rules/${id}`, {
    method: 'DELETE',
  });
}

export function fetchNotificationDeliveries(limit = 50): Promise<{ deliveries: NotificationDelivery[] }> {
  return fetchAuth<{ deliveries: NotificationDelivery[] }>(
    `${MGMT_BASE}/notifications/deliveries?limit=${limit}`,
  );
}

// ─── Changelog (public — no auth required) ────────────────────────────────────

export interface ChangelogSection {
  label: string;
  items: string[];
}

export interface ChangelogEntry {
  version: string;
  date: string | null;
  sections: ChangelogSection[];
}

export function fetchChangelog(): Promise<ChangelogEntry[]> {
  return fetchJson<ChangelogEntry[]>(`${MGMT_BASE}/changelog`);
}
