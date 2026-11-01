import { useState } from "react";
import {
  apiRequest,
  type AuditEntry,
  type Dashboard,
  type Invitation,
  type PlatformAdmin,
  type PlatformSettings,
} from "../api.ts";
import { useAuth } from "../auth-context.ts";
import { Field } from "../components.tsx";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";

function AuditTable({ entries }: { entries: AuditEntry[] }) {
  return (
    <table tabIndex={0}>
      <thead>
        <tr>
          <th>Time</th>
          <th>Action</th>
          <th>Actor</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr key={entry.id}>
            <td>{formatDate(entry.at)}</td>
            <td>{entry.action}</td>
            <td>{entry.actor_email ?? entry.actor_kind}</td>
            <td>
              <code>{Object.keys(entry.details).length ? JSON.stringify(entry.details) : "—"}</code>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AdminDashboardPage() {
  const { data, error } = useLoad<Dashboard>("/api/admin/dashboard");
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <section>
      <h1>Platform dashboard</h1>
      <div className="stats">
        <div className="stat">
          <span className="stat-value">{data.organizations_by_status.ACTIVE ?? 0}</span>
          <span>Active organizations</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.organizations_by_status.SUSPENDED ?? 0}</span>
          <span>Suspended organizations</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.active_admins}</span>
          <span>Active platform administrators</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.pending_invitations}</span>
          <span>Pending invitations</span>
        </div>
      </div>
      <div className="stats">
        <div className="stat">
          <span className="stat-value">{data.organizations_created_30d}</span>
          <span>Organizations created (30 days)</span>
        </div>
        <div className="stat">
          <span className="stat-value">
            {data.monitors_active} / {data.monitors_total}
          </span>
          <span>Active / total monitors</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.queue.checks_per_minute}</span>
          <span>Checks per minute</span>
        </div>
        <div className="stat">
          <span className="stat-value">
            {data.open_incidents_by_severity.CRITICAL ?? 0} / {data.open_incidents_by_severity.WARNING ?? 0}
          </span>
          <span>Open incidents (critical / warning)</span>
        </div>
      </div>
      <h2>Processing health</h2>
      <dl className="details">
        <dt>Due checks waiting</dt>
        <dd>
          {data.queue.due_backlog}
          {data.queue.claim_lag_seconds !== null ? ` (oldest ${String(Math.round(data.queue.claim_lag_seconds))} s)` : ""}
        </dd>
        <dt>Checks running</dt>
        <dd>{data.queue.checks_in_flight}</dd>
        <dt>Checks (24 h)</dt>
        <dd>{data.queue.checks_last_24h}</dd>
        <dt>Notifications queued</dt>
        <dd>
          {data.queue.outbox_pending} pending · {data.queue.outbox_leased} sending
          {data.queue.outbox_lag_seconds !== null ? ` · oldest due ${String(Math.round(data.queue.outbox_lag_seconds))} s` : ""}
        </dd>
        <dt>Failed notifications (24 h)</dt>
        <dd>{data.queue.outbox_failed_24h}</dd>
        <dt>Workers</dt>
        <dd>
          {data.workers.length === 0
            ? "No heartbeats in the last day"
            : data.workers
                .map((w) => `${w.kind.toLowerCase()} ${w.alive ? "alive" : "stale"} (${String(w.in_flight)} running)`)
                .join(", ")}
        </dd>
      </dl>
      <h2>Usage against limits</h2>
      {data.organizations.length === 0 ? (
        <p>No organizations yet.</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Organization</th>
              <th>Status</th>
              <th>Monitors</th>
              <th>Status pages</th>
              <th>Channels</th>
              <th>Open incidents</th>
            </tr>
          </thead>
          <tbody>
            {data.organizations.map((o) => (
              <tr key={o.organization_id}>
                <td>
                  {o.name}
                  <div className="muted">{o.slug}</div>
                </td>
                <td>{o.status}</td>
                <td>
                  {o.monitors_live} / {o.max_monitors}
                </td>
                <td>
                  {o.status_pages} / {o.max_status_pages}
                </td>
                <td>
                  {o.channels} / {o.max_channels}
                </td>
                <td>{o.open_incidents_critical + o.open_incidents_warning}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h2>Daily activity (30 days)</h2>
      {data.usage_daily.length === 0 ? (
        <p>No activity yet.</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Day (UTC)</th>
              <th>Checks</th>
              <th>Failed</th>
              <th>Incidents</th>
              <th>Notifications sent</th>
              <th>Notification failures</th>
            </tr>
          </thead>
          <tbody>
            {data.usage_daily.map((d) => (
              <tr key={d.day}>
                <td>{d.day}</td>
                <td>{d.checks}</td>
                <td>{d.failed_checks}</td>
                <td>{d.incidents_opened}</td>
                <td>{d.notifications_sent}</td>
                <td>{d.notification_failures}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h2>Recent platform activity</h2>
      <AuditTable entries={data.recent_audit} />
    </section>
  );
}

export function AdminAdminsPage() {
  const { me } = useAuth();
  const { data, error, reload } = useLoad<{ admins: PlatformAdmin[]; invitations: Invitation[] }>(
    "/api/admin/platform-admins",
  );
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const run = async (action: () => Promise<unknown>, success: string) => {
    setActionError(null);
    setMessage(null);
    try {
      await action();
      setMessage(success);
      reload();
    } catch (err) {
      setActionError(errorMessage(err));
    }
  };

  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <section>
      <h1>Platform administrators</h1>
      {message && <p role="status">{message}</p>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          void run(async () => {
            await apiRequest("POST", "/api/admin/platform-admins", { email });
            setEmail("");
          }, "Invitation sent. It expires in 24 hours.");
        }}
      >
        <Field label="Invite by email" type="email" value={email} onChange={setEmail} />
        <button type="submit">Send invitation</button>
      </form>
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Email</th>
            <th>Status</th>
            <th>Granted</th>
            <th>Granted by</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.admins.map((admin) => (
            <tr key={admin.user_id}>
              <td>{admin.email}</td>
              <td>
                {admin.status}
                {admin.user_status !== "ACTIVE" ? ` (${admin.user_status})` : ""}
              </td>
              <td>{formatDate(admin.granted_at)}</td>
              <td>{admin.granted_by_email ?? "bootstrap"}</td>
              <td>
                {admin.status === "ACTIVE" && admin.user_id !== me?.id && (
                  <button
                    type="button"
                    className="danger"
                    onClick={() => {
                      if (window.confirm(`Deactivate ${admin.email}? Their sessions end now.`)) {
                        void run(
                          () =>
                            apiRequest("POST", `/api/admin/platform-admins/${admin.user_id}/deactivate`),
                          `${admin.email} was deactivated.`,
                        );
                      }
                    }}
                  >
                    Deactivate
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Pending invitations</h2>
      {data.invitations.length === 0 ? (
        <p>No pending invitations.</p>
      ) : (
        <ul className="plain">
          {data.invitations.map((invitation) => (
            <li key={invitation.id}>
              {invitation.email}, expires {formatDate(invitation.expires_at)}{" "}
              <button
                type="button"
                onClick={() => {
                  void run(
                    () =>
                      apiRequest(
                        "POST",
                        `/api/admin/platform-admins/invitations/${invitation.id}/revoke`,
                      ),
                    "Invitation revoked.",
                  );
                }}
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const SETTINGS_LABELS: [keyof Omit<PlatformSettings, "version" | "updated_at">, string][] = [
  ["default_max_monitors", "Default max monitors per organization"],
  ["min_interval_seconds", "Minimum check interval (seconds: 60, 120 or 300)"],
  ["max_timeout_ms", "Maximum timeout (ms, 3000–15000)"],
  ["max_retry_attempts", "Maximum retry attempts (0–2)"],
  ["max_custom_headers", "Maximum custom headers (0–5)"],
  ["validation_max_bytes", "Response validation byte cap"],
  ["check_now_per_monitor_seconds", "Check-now: seconds between runs per monitor"],
  ["check_now_per_org_hour", "Check-now: runs per organization per hour"],
  ["default_max_status_pages", "Default max status pages per organization"],
  ["default_max_channels", "Default max notification channels per organization"],
];

export function AdminSettingsPage() {
  const { data, error, reload } = useLoad<PlatformSettings>("/api/admin/settings");
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [message, setMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;

  const value = (key: string) => draft[key] ?? String(data[key as keyof PlatformSettings]);
  return (
    <form
      className="card wide"
      onSubmit={(event) => {
        event.preventDefault();
        setMessage(null);
        setSaveError(null);
        const body: Record<string, number> = { version: data.version };
        for (const [key] of SETTINGS_LABELS) {
          body[key] = Number(value(key));
        }
        apiRequest("PUT", "/api/admin/settings", body).then(
          () => {
            setDraft({});
            setMessage("Settings saved.");
            reload();
          },
          (err: unknown) => {
            setSaveError(errorMessage(err));
          },
        );
      }}
    >
      <h1>Platform settings</h1>
      <p className="hint">
        Limits apply to organizations from G2 onward. SSRF protections are not configurable.
      </p>
      {message && <p role="status">{message}</p>}
      {saveError && <p role="alert" className="error">{saveError}</p>}
      {SETTINGS_LABELS.map(([key, label]) => (
        <Field
          key={key}
          label={label}
          type="number"
          value={value(key)}
          onChange={(next) => {
            setDraft((current) => ({ ...current, [key]: next }));
          }}
        />
      ))}
      <button type="submit">Save settings</button>
    </form>
  );
}

export function AdminAuditPage() {
  const { data, error } = useLoad<AuditEntry[]>("/api/admin/audit?limit=100");
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <section>
      <h1>Platform audit history</h1>
      <AuditTable entries={data} />
    </section>
  );
}
