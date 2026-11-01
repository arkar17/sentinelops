export type ApiStatus = "checking" | "ok" | "unavailable";

/** Calls the API liveness endpoint. Never throws; network errors map to "unavailable". */
export async function fetchApiStatus(signal?: AbortSignal): Promise<ApiStatus> {
  try {
    const response = await fetch("/healthz", signal ? { signal } : {});
    return response.ok ? "ok" : "unavailable";
  } catch {
    return "unavailable";
  }
}

/** Error envelope returned by the API: {"error": {code, message, request_id}}. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIES = ["__Host-sentinelops_csrf", "sentinelops_csrf"];

export function readCsrfToken(cookies: string = document.cookie): string | undefined {
  for (const part of cookies.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name && CSRF_COOKIES.includes(name)) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return undefined;
}

export async function apiRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (UNSAFE.has(method)) {
    const csrf = readCsrfToken();
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
  }
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  if (response.status === 204) {
    return undefined as T;
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const error = (payload as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError(
      response.status,
      error?.code ?? "UNKNOWN",
      error?.message ?? "Something went wrong. Try again.",
    );
  }
  return payload as T;
}

export interface Me {
  id: string;
  email: string;
  is_platform_admin: boolean;
  mfa_pending?: "VERIFY" | "ENROLL" | null;
}

export interface AuditEntry {
  id: string;
  at: string;
  action: string;
  actor_kind: string;
  actor_email: string | null;
  entity_kind: string | null;
  entity_id: string | null;
  details: Record<string, unknown>;
  request_id: string | null;
}

export interface Dashboard {
  organizations_by_status: Record<string, number>;
  active_admins: number;
  pending_invitations: number;
  recent_audit: AuditEntry[];
  organizations_created_30d: number;
  monitors_total: number;
  monitors_active: number;
  open_incidents_by_severity: Record<string, number>;
  queue: {
    checks_per_minute: number;
    checks_last_24h: number;
    due_backlog: number;
    claim_lag_seconds: number | null;
    checks_in_flight: number;
    outbox_pending: number;
    outbox_leased: number;
    outbox_lag_seconds: number | null;
    outbox_failed_24h: number;
  };
  workers: { worker_id: string; kind: string; last_seen_at: string; in_flight: number; alive: boolean }[];
  usage_daily: {
    day: string;
    checks: number;
    failed_checks: number;
    blocked_checks: number;
    inconclusive_checks: number;
    incidents_opened: number;
    notifications_sent: number;
    notification_failures: number;
  }[];
  organizations: {
    organization_id: string;
    slug: string;
    name: string;
    status: string;
    active_members: number;
    monitors_live: number;
    monitors_active: number;
    max_monitors: number;
    status_pages: number;
    max_status_pages: number;
    channels: number;
    max_channels: number;
    open_incidents_critical: number;
    open_incidents_warning: number;
  }[];
}

export interface PlatformAdmin {
  user_id: string;
  email: string;
  user_status: string;
  status: string;
  granted_at: string;
  granted_by_email: string | null;
  deactivated_at: string | null;
}

export interface Invitation {
  id: string;
  email: string;
  invited_by_email: string;
  created_at: string;
  expires_at: string;
}

export interface PlatformSettings {
  default_max_monitors: number;
  min_interval_seconds: number;
  max_timeout_ms: number;
  max_retry_attempts: number;
  max_custom_headers: number;
  validation_max_bytes: number;
  check_now_per_monitor_seconds: number;
  check_now_per_org_hour: number;
  default_max_status_pages: number;
  default_max_channels: number;
  version: number;
  updated_at: string;
}

export type OrgRole = "ORG_OWNER" | "ORG_ADMIN" | "ORG_MEMBER" | "VIEWER";

export interface Membership {
  organization_id: string;
  slug: string;
  name: string;
  organization_status: string;
  role: OrgRole;
}

export interface MyOrganizations {
  organizations: Membership[];
  selected_org_id: string | null;
}

export interface Limits {
  max_monitors: number;
  min_interval_seconds: number;
  max_status_pages: number;
  max_channels: number;
}

export interface OrgProfile {
  id: string;
  slug: string;
  name: string;
  timezone: string;
  status: string;
  version: number;
  my_role: OrgRole;
  limits: Limits;
  member_count: number;
  project_count: number;
}

export interface Member {
  user_id: string;
  email: string;
  role: OrgRole;
  status: string;
  joined_at: string;
}

export interface OrgInvitation {
  id: string;
  email: string;
  role: OrgRole;
  invited_by_email: string;
  created_at: string;
  expires_at: string;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  archived_at: string | null;
  created_at: string;
  version: number;
}

export interface OrgAuditEntry {
  id: string;
  at: string;
  scope: string;
  action: string;
  actor_plane: string;
  actor_email: string | null;
  details: Record<string, unknown>;
}

export interface OrgMetadata {
  id: string;
  slug: string;
  name: string;
  timezone: string;
  status: string;
  suspended_at: string | null;
  suspended_reason: string | null;
  created_at: string;
  version: number;
  owner_emails: string[];
  member_count: number;
  project_count: number;
  pending_owner_invitation: boolean;
  limit_overrides: Record<keyof Limits, number | null>;
  effective_limits: Limits;
}

export interface MonitorConfig {
  display_url: string;
  method: "GET" | "HEAD";
  interval_seconds: number;
  timeout_ms: number;
  retry_attempts: number;
  expected_status: [number, number][];
  validation: Record<string, unknown> | null;
  latency_threshold_ms: number | null;
  failure_threshold: number;
  recovery_threshold: number;
  tls_warn_days: number;
  header_count: number;
  tags: string[];
}

export interface LatestResult {
  result: string;
  failure_category: string | null;
  http_status: number | null;
  elapsed_ms: number | null;
  observed_at: string;
}

export interface Monitor {
  id: string;
  name: string;
  project_id: string;
  hostname: string;
  lifecycle: "DRAFT" | "ACTIVE" | "PAUSED" | "ARCHIVED";
  paused_reason: string | null;
  attention_reason: string | null;
  health_state: string;
  latest: LatestResult | null;
  version: number;
  config: MonitorConfig | null;
}

export interface Measurement {
  id: string;
  trigger: string;
  scheduled_for: string | null;
  observed_at: string;
  result: string;
  failure_category: string | null;
  http_status: number | null;
  elapsed_ms: number | null;
  attempt_count: number;
  tls_not_after: string | null;
}

export interface Domain {
  id: string;
  fqdn: string;
  method: "DNS_TXT" | "ADMIN_EXCEPTION";
  status: string;
  challenge_expires_at: string | null;
  verified_at: string | null;
  expires_at: string | null;
  last_checked_at: string | null;
  exception_reason: string | null;
}

export interface Challenge {
  domain: Domain;
  record_type: string;
  record_name: string;
  record_value: string;
}

export interface DomainExceptionRequest {
  id: string;
  organization_id: string;
  organization_slug: string;
  organization_name: string;
  fqdn: string;
  reason: string | null;
  requested_at: string;
}

export type IncidentStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";

export interface Incident {
  id: string;
  type: "OUTAGE" | "TLS_EXPIRY";
  severity: "CRITICAL" | "WARNING";
  status: IncidentStatus;
  source_kind: string;
  title: string;
  monitor: { id: string; name: string; hostname: string };
  opened_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  resolution: "AUTO" | "MANUAL" | null;
  assigned_user_id: string | null;
  assignee_email: string | null;
  last_event_at: string;
  duration_seconds: number | null;
  duration_is_estimate: boolean;
  version: number;
}

export interface IncidentPage {
  items: Incident[];
  total: number;
}

export interface IncidentEvent {
  id: string;
  event_type: "OPENED" | "ACKNOWLEDGED" | "ASSIGNED" | "UNASSIGNED" | "COMMENTED" | "RESOLVED";
  actor_kind: "USER" | "SYSTEM";
  actor_user_id: string | null;
  actor_email: string | null;
  created_at: string;
  details: Record<string, unknown>;
}

export interface IncidentDetail extends Incident {
  monitor_health: string;
  monitor_lifecycle: string;
  events: IncidentEvent[];
}

export type NotifyEvent =
  | "INCIDENT_OPENED"
  | "TLS_EXPIRY_WARNING"
  | "INCIDENT_ACKNOWLEDGED"
  | "INCIDENT_RESOLVED"
  | "MONITOR_AUTO_PAUSED";

export interface NotificationChannel {
  id: string;
  type: "TELEGRAM" | "EMAIL";
  label: string;
  enabled: boolean;
  credentials_set: boolean;
  recipients: { user_id: string; email: string }[];
  created_at: string;
  version: number;
}

export interface NotificationRoute {
  id: string;
  channel_id: string;
  project_id: string | null;
  monitor_id: string | null;
  event_types: NotifyEvent[];
  enabled: boolean;
  version: number;
}

export interface DeliveryItem {
  id: string;
  channel_id: string;
  event_type: string;
  incident_id: string | null;
  monitor_id: string | null;
  state: "PENDING" | "LEASED" | "SENT" | "FAILED" | "CANCELLED";
  cancel_reason: string | null;
  attempts: number;
  last_result_code: string | null;
  created_at: string;
  next_attempt_at: string;
  sent_at: string | null;
  history: { attempt: number; result_code: string; attempted_at: string }[];
}

export interface StatusPageConfig {
  id: string;
  title: string;
  public_slug: string;
  published: boolean;
  monitors: { monitor_id: string; monitor_name: string; public_display_name: string; sort_order: number }[];
  created_at: string;
  version: number;
}

export type PublicStatus = "OPERATIONAL" | "DEGRADED" | "OUTAGE" | "UNKNOWN";

export interface PublicStatusPage {
  title: string;
  generated_at: string;
  overall: PublicStatus;
  components: { name: string; status: PublicStatus; uptime_24h: number | null; uptime_7d: number | null }[];
  active_incidents: { title: string; component: string; status: string; started_at: string }[];
  recent_incidents: { title: string; component: string; started_at: string; resolved_at: string | null }[];
}

export interface ReportStats {
  conclusive_samples: number;
  available_samples: number;
  failed_samples: number;
  blocked_samples: number;
  inconclusive_samples: number;
  expected_samples: number;
  missed_samples: number;
  uptime_pct: number | null;
  coverage_pct: number | null;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  downtime_estimate_seconds: number;
  outage_incident_seconds: number;
  incidents_opened: number;
  outage_incidents_opened: number;
  tls_incidents_opened: number;
  incidents_resolved: number;
  mean_resolution_seconds: number | null;
  mean_acknowledge_seconds: number | null;
}

export interface ReportWindow {
  period: string;
  start: string;
  end: string;
  bucket: "hour" | "day";
  timezone: string;
  latency_method: "exact" | "approximate";
}

export interface ReportPoint {
  bucket_start: string;
  conclusive_samples: number;
  available_samples: number;
  uptime_pct: number | null;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
}

export interface ReportResponse {
  window: ReportWindow;
  summary: ReportStats;
  median_resolution_seconds: number | null;
  monitors: {
    monitor_id: string;
    name: string;
    hostname: string;
    project_id: string;
    project_name: string;
    lifecycle: string;
    interval_seconds: number;
    stats: ReportStats;
  }[];
  total_monitors: number;
  series: ReportPoint[];
}

export interface OrgDashboard {
  generated_at: string;
  monitors_by_lifecycle: Record<string, number>;
  health: Record<string, number>;
  active_incidents_by_severity: Record<string, number>;
  recent_incidents: {
    id: string;
    monitor_id: string;
    monitor_name: string;
    type: string;
    severity: string;
    status: string;
    title: string;
    opened_at: string;
    resolved_at: string | null;
  }[];
  results_24h: Record<string, number>;
  summary_24h: ReportStats;
  window_24h: ReportWindow;
  series_24h: ReportPoint[];
  tls_expiring: {
    monitor_id: string;
    monitor_name: string;
    hostname: string;
    expires_at: string;
    days_remaining: number;
    warn_days: number;
  }[];
  recent_checks: {
    monitor_id: string;
    monitor_name: string;
    result: string;
    failure_category: string | null;
    http_status: number | null;
    elapsed_ms: number | null;
    trigger: string;
    observed_at: string;
  }[];
}

export interface Availability {
  monitor_id: string;
  periods: Record<string, ReportStats>;
}
