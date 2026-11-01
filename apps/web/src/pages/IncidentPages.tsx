import { useState } from "react";
import {
  apiRequest,
  type Incident,
  type IncidentDetail,
  type IncidentEvent,
  type IncidentPage,
  type Member,
  type OrgRole,
} from "../api.ts";
import { useAuth } from "../auth-context.ts";
import { Link } from "../components.tsx";
import { errorMessage, formatDate, formatDuration } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { can } from "../permissions.ts";

const TYPE_LABELS: Record<string, string> = {
  OUTAGE: "Outage",
  TLS_EXPIRY: "TLS certificate expiry",
};
const STATUS_LABELS: Record<string, string> = {
  OPEN: "Open",
  ACKNOWLEDGED: "Acknowledged",
  RESOLVED: "Resolved",
};
const SEVERITY_LABELS: Record<string, string> = { CRITICAL: "Critical", WARNING: "Warning" };

function duration(incident: Incident): string {
  if (incident.duration_seconds === null) return "Ongoing";
  const text = formatDuration(incident.duration_seconds);
  return incident.duration_is_estimate ? `${text} (estimated)` : text;
}

export function IncidentTable({ items, base }: { items: Incident[]; base: string }) {
  return (
    <table tabIndex={0}>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Incident</th>
          <th>Monitor</th>
          <th>Status</th>
          <th>Opened</th>
          <th>Duration</th>
          <th>Assignee</th>
        </tr>
      </thead>
      <tbody>
        {items.map((incident) => (
          <tr key={incident.id} data-status={incident.status}>
            <td data-severity={incident.severity}>{SEVERITY_LABELS[incident.severity]}</td>
            <td>
              <Link to={`${base}/incidents/${incident.id}`}>{incident.title}</Link>
              <div className="muted">{TYPE_LABELS[incident.type]}</div>
            </td>
            <td>
              <Link to={`${base}/monitors/${incident.monitor.id}`}>{incident.monitor.name}</Link>
              <div className="muted">{incident.monitor.hostname}</div>
            </td>
            <td>{STATUS_LABELS[incident.status]}</td>
            <td>{formatDate(incident.opened_at)}</td>
            <td>{duration(incident)}</td>
            <td>{incident.assignee_email ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

type View = "active" | "resolved" | "all";

export function IncidentList({ orgPath, base }: { orgPath: string; base: string }) {
  const { me } = useAuth();
  const [view, setView] = useState<View>("active");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [mine, setMine] = useState(false);
  const params = new URLSearchParams({ limit: "100" });
  if (view !== "all") params.set("active", view === "active" ? "true" : "false");
  if (type) params.set("type", type);
  if (severity) params.set("severity", severity);
  if (mine && me) params.set("assigned_user_id", me.id);
  const { data, error } = useLoad<IncidentPage>(`${orgPath}/incidents?${params.toString()}`);

  return (
    <section>
      <h1>Incidents</h1>
      <div className="inline-form" role="group" aria-label="Filters">
        <label className="field">
          <span>Show</span>
          <select
            value={view}
            onChange={(event) => {
              setView(event.target.value as View);
            }}
          >
            <option value="active">Active</option>
            <option value="resolved">Resolved</option>
            <option value="all">All</option>
          </select>
        </label>
        <label className="field">
          <span>Type</span>
          <select
            value={type}
            onChange={(event) => {
              setType(event.target.value);
            }}
          >
            <option value="">Any type</option>
            <option value="OUTAGE">Outage</option>
            <option value="TLS_EXPIRY">TLS certificate expiry</option>
          </select>
        </label>
        <label className="field">
          <span>Severity</span>
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
            }}
          >
            <option value="">Any severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="WARNING">Warning</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={mine}
            onChange={(event) => {
              setMine(event.target.checked);
            }}
          />{" "}
          Assigned to me
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!data && !error && <p role="status">Loading…</p>}
      {data && data.items.length === 0 && (
        <p>{view === "active" ? "No active incidents." : "No incidents match these filters."}</p>
      )}
      {data && data.items.length > 0 && (
        <>
          <p className="muted">
            Showing {data.items.length} of {data.total}
          </p>
          <IncidentTable items={data.items} base={base} />
        </>
      )}
    </section>
  );
}

/** Incidents of one monitor, for the monitor detail page. */
export function MonitorIncidents({
  orgPath,
  base,
  monitorId,
}: {
  orgPath: string;
  base: string;
  monitorId: string;
}) {
  const { data, error } = useLoad<IncidentPage>(
    `${orgPath}/incidents?monitor_id=${monitorId}&limit=20`,
  );
  return (
    <>
      <h2>Incidents</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {data && data.items.length === 0 && <p>No incidents for this monitor.</p>}
      {data && data.items.length > 0 && <IncidentTable items={data.items} base={base} />}
    </>
  );
}

function describe(event: IncidentEvent, members: Map<string, string>): string {
  const d = event.details;
  const who = (key: string) => {
    const id = d[key];
    return typeof id === "string" ? (members.get(id) ?? "a former member") : "nobody";
  };
  switch (event.event_type) {
    case "OPENED":
      return typeof d.days_remaining === "number"
        ? `Opened: certificate expires in ${String(d.days_remaining)} days (threshold ${String(d.threshold_days)})`
        : `Opened after ${String(d.consecutive_failures)} consecutive failed checks`;
    case "ACKNOWLEDGED":
      return "Acknowledged";
    case "ASSIGNED":
      return `Assigned to ${who("assignee_user_id")}`;
    case "UNASSIGNED":
      return d.reason === "MEMBERSHIP_INACTIVE"
        ? "Unassigned because the assignee is no longer an active member"
        : "Unassigned";
    case "COMMENTED":
      return "Note";
    case "RESOLVED":
      if (d.resolution === "MANUAL") return "Resolved manually";
      return typeof d.days_remaining === "number"
        ? `Resolved: renewed certificate expires in ${String(d.days_remaining)} days`
        : `Resolved after ${String(d.consecutive_successes)} consecutive successful checks`;
  }
}

interface Evidence {
  result?: string;
  failure_category?: string | null;
  http_status?: number | null;
  elapsed_ms?: number | null;
  observed_at?: string;
}

function EvidenceList({ evidence }: { evidence: Evidence }) {
  return (
    <dl className="details">
      <dt>Result</dt>
      <dd>
        {evidence.result ?? "—"}
        {evidence.failure_category ? ` (${evidence.failure_category})` : ""}
      </dd>
      <dt>HTTP status</dt>
      <dd>{evidence.http_status ?? "—"}</dd>
      <dt>Response time</dt>
      <dd>{evidence.elapsed_ms != null ? `${String(evidence.elapsed_ms)} ms` : "—"}</dd>
      <dt>Observed</dt>
      <dd>{evidence.observed_at ? formatDate(evidence.observed_at) : "—"}</dd>
    </dl>
  );
}

export function IncidentDetailPage({
  orgPath,
  base,
  id,
  role,
}: {
  orgPath: string;
  base: string;
  id: string;
  role: OrgRole;
}) {
  const path = `${orgPath}/incidents/${id}`;
  const incident = useLoad<IncidentDetail>(path);
  const members = useLoad<Member[]>(`${orgPath}/members`);
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [resolveNote, setResolveNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (incident.error) return <p role="alert" className="error">{incident.error}</p>;
  if (!incident.data) return <p role="status">Loading…</p>;
  const i = incident.data;
  const resolved = i.status === "RESOLVED";
  const emails = new Map((members.data ?? []).map((m) => [m.user_id, m.email]));
  const active = (members.data ?? []).filter((m) => m.status === "ACTIVE");
  const stillDown =
    i.type === "OUTAGE" && i.monitor_lifecycle === "ACTIVE" && i.monitor_health === "DOWN";
  const opened = i.events.find((e) => e.event_type === "OPENED");
  const evidence = (opened?.details.evidence ?? null) as Evidence | null;

  const run = (method: string, suffix: string, body: unknown, success: string, after?: () => void) => {
    setBusy(true);
    setMessage(null);
    setError(null);
    apiRequest(method, `${path}/${suffix}`, body).then(
      () => {
        setMessage(success);
        after?.();
        incident.reload();
      },
      (err: unknown) => {
        setError(errorMessage(err));
        incident.reload();
      },
    ).finally(() => {
      setBusy(false);
    });
  };

  return (
    <section>
      <p>
        <Link to={`${base}/incidents`}>← Incidents</Link>
      </p>
      <h1>{i.title}</h1>
      <p className="muted">
        {SEVERITY_LABELS[i.severity]} · {TYPE_LABELS[i.type]} · {STATUS_LABELS[i.status]}
      </p>
      {message && <p role="status">{message}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <dl className="details">
        <dt>Monitor</dt>
        <dd>
          <Link to={`${base}/monitors/${i.monitor.id}`}>{i.monitor.name}</Link> ({i.monitor.hostname}) ·
          health {i.monitor_lifecycle === "PAUSED" ? "paused" : i.monitor_health.toLowerCase()}
        </dd>
        <dt>Opened</dt>
        <dd>{formatDate(i.opened_at)}</dd>
        {i.acknowledged_at && (
          <>
            <dt>Acknowledged</dt>
            <dd>{formatDate(i.acknowledged_at)}</dd>
          </>
        )}
        {i.resolved_at && (
          <>
            <dt>Resolved</dt>
            <dd>
              {formatDate(i.resolved_at)} ({i.resolution === "AUTO" ? "automatically" : "manually"})
            </dd>
          </>
        )}
        <dt>Duration</dt>
        <dd>{duration(i)}</dd>
        <dt>Assignee</dt>
        <dd>{i.assignee_email ?? "Unassigned"}</dd>
      </dl>
      {i.duration_is_estimate && i.duration_seconds !== null && (
        <p className="hint">
          Outage duration is estimated from the failed and recovered checks, not exact downtime.
        </p>
      )}

      {!resolved && (
        <div className="inline-form">
          {can(role, "INC.acknowledge") && i.status === "OPEN" && (
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                run("POST", "acknowledge", { version: i.version }, "Incident acknowledged.");
              }}
            >
              Acknowledge
            </button>
          )}
          {can(role, "INC.assign") && (
            <>
              <label className="field">
                <span>Assign to</span>
                <select
                  value={assignee}
                  onChange={(event) => {
                    setAssignee(event.target.value);
                  }}
                >
                  <option value="">Choose a member…</option>
                  {active.map((m) => (
                    <option key={m.user_id} value={m.user_id}>
                      {m.email}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                disabled={busy || !assignee}
                onClick={() => {
                  run("POST", "assign", { user_id: assignee, version: i.version }, "Incident assigned.", () => {
                    setAssignee("");
                  });
                }}
              >
                Assign
              </button>
              {i.assigned_user_id && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    run("POST", "assign", { user_id: null, version: i.version }, "Incident unassigned.");
                  }}
                >
                  Unassign
                </button>
              )}
            </>
          )}
        </div>
      )}

      {!resolved && can(role, "INC.resolve") && (
        <div className="inline-form">
          {stillDown ? (
            <p className="hint">
              This outage resolves automatically when the monitor recovers. While it is down you can
              acknowledge the incident or pause the monitor.
            </p>
          ) : (
            <>
              <label className="field">
                <span>Resolution note (optional)</span>
                <input
                  value={resolveNote}
                  maxLength={2000}
                  onChange={(event) => {
                    setResolveNote(event.target.value);
                  }}
                />
              </label>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  const body = resolveNote.trim()
                    ? { note: resolveNote.trim(), version: i.version }
                    : { version: i.version };
                  run("POST", "resolve", body, "Incident resolved.", () => {
                    setResolveNote("");
                  });
                }}
              >
                Resolve
              </button>
            </>
          )}
        </div>
      )}

      {evidence && (
        <>
          <h2>Evidence</h2>
          <EvidenceList evidence={evidence} />
        </>
      )}

      <h2>Timeline</h2>
      <ol className="timeline">
        {i.events.map((event) => (
          <li key={event.id} data-event={event.event_type}>
            <span className="muted">{formatDate(event.created_at)}</span>{" "}
            <strong>{event.actor_kind === "SYSTEM" ? "SentinelOps" : (event.actor_email ?? "A member")}</strong>{" "}
            {describe(event, emails)}
            {typeof event.details.text === "string" && <p className="note">{event.details.text}</p>}
            {typeof event.details.note === "string" && <p className="note">{event.details.note}</p>}
          </li>
        ))}
      </ol>

      {can(role, "INC.comment") && (
        <form
          className="note-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!note.trim()) return;
            run("POST", "comments", { text: note.trim() }, "Note added.", () => {
              setNote("");
            });
          }}
        >
          <label className="field">
            <span>Add a note</span>
            <textarea
              value={note}
              maxLength={2000}
              rows={3}
              onChange={(event) => {
                setNote(event.target.value);
              }}
            />
          </label>
          <button type="submit" disabled={busy || !note.trim()}>
            Add note
          </button>
        </form>
      )}
    </section>
  );
}
