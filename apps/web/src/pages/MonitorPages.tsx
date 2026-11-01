import { useState } from "react";
import {
  apiRequest,
  type Availability,
  type Measurement,
  type Monitor,
  type OrgRole,
  type Project,
} from "../api.ts";
import { Field, Link } from "../components.tsx";
import { errorMessage, formatDate, pct } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { can } from "../permissions.ts";
import { MonitorIncidents } from "./IncidentPages.tsx";
import { navigate } from "../router.ts";

const RESULT_LABELS: Record<string, string> = {
  PASS: "Pass",
  SLOW: "Slow",
  FAIL: "Fail",
  BLOCKED: "Blocked by policy",
  INCONCLUSIVE: "Inconclusive",
};

function statusOf(monitor: Monitor): string {
  if (monitor.lifecycle === "PAUSED") {
    return monitor.paused_reason === "POLICY_BLOCKED" ? "Paused (blocked by policy)" : "Paused";
  }
  if (monitor.lifecycle === "DRAFT") return "Waiting for domain verification";
  if (monitor.lifecycle === "ARCHIVED") return "Archived";
  return monitor.latest ? (RESULT_LABELS[monitor.latest.result] ?? monitor.latest.result) : "No checks yet";
}

function Banner({ message, error }: { message: string | null; error: string | null }) {
  return (
    <>
      {message && <p role="status">{message}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </>
  );
}

export function MonitorList({ orgPath, base, role }: { orgPath: string; base: string; role: OrgRole }) {
  const { data, error } = useLoad<Monitor[]>(`${orgPath}/monitors`);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <>
      <h1>Monitors</h1>
      {can(role, "MON.manage") && (
        <p>
          <Link to={`${base}/monitors/new`}>New monitor</Link>
        </p>
      )}
      {data.length === 0 ? (
        <p>No monitors yet.{can(role, "MON.manage") ? " Create one to start checking an endpoint." : ""}</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Host</th>
              <th>Status</th>
              <th>Last response</th>
              <th>Last check</th>
            </tr>
          </thead>
          <tbody>
            {data.map((monitor) => (
              <tr key={monitor.id}>
                <td>
                  <Link to={`${base}/monitors/${monitor.id}`}>{monitor.name}</Link>
                </td>
                <td>{monitor.hostname}</td>
                <td data-result={monitor.latest?.result ?? ""}>{statusOf(monitor)}</td>
                <td>
                  {monitor.latest?.http_status ?? "—"}
                  {monitor.latest?.elapsed_ms != null ? ` · ${String(monitor.latest.elapsed_ms)} ms` : ""}
                </td>
                <td>{monitor.latest ? formatDate(monitor.latest.observed_at) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

interface FormState {
  name: string;
  project_id: string;
  url: string;
  method: "GET" | "HEAD";
  interval_seconds: string;
  timeout_seconds: string;
  retry_attempts: string;
  expected_status: string;
  validation_type: "" | "substring" | "json_path";
  validation_value: string;
  validation_path: string;
  latency_threshold_ms: string;
}

const EMPTY_FORM: FormState = {
  name: "",
  project_id: "",
  url: "https://",
  method: "GET",
  interval_seconds: "60",
  timeout_seconds: "10",
  retry_attempts: "1",
  expected_status: "200-299",
  validation_type: "",
  validation_value: "",
  validation_path: "$.status",
  latency_threshold_ms: "",
};

/** Expected JSON values are typed as JSON (42, true, null, "text"); bare text stays a string. */
function parseJsonValue(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

function toPayload(form: FormState): Record<string, unknown> {
  let validation: Record<string, unknown> | null = null;
  if (form.validation_type === "substring") {
    validation = { type: "substring", value: form.validation_value };
  } else if (form.validation_type === "json_path") {
    validation = { type: "json_path", path: form.validation_path, equals: parseJsonValue(form.validation_value) };
  }
  return {
    name: form.name,
    project_id: form.project_id,
    url: form.url,
    method: form.method,
    interval_seconds: Number(form.interval_seconds),
    timeout_ms: Math.round(Number(form.timeout_seconds) * 1000),
    retry_attempts: Number(form.retry_attempts),
    expected_status: form.expected_status
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    validation,
    latency_threshold_ms: form.latency_threshold_ms ? Number(form.latency_threshold_ms) : null,
  };
}

function fromMonitor(monitor: Monitor, url: string): FormState {
  const config = monitor.config;
  const validation = config?.validation ?? null;
  return {
    name: monitor.name,
    project_id: monitor.project_id,
    url,
    method: config?.method ?? "GET",
    interval_seconds: String(config?.interval_seconds ?? 60),
    timeout_seconds: String((config?.timeout_ms ?? 10000) / 1000),
    retry_attempts: String(config?.retry_attempts ?? 1),
    expected_status: (config?.expected_status ?? [[200, 299]])
      .map(([low, high]) => (low === high ? String(low) : `${String(low)}-${String(high)}`))
      .join(", "),
    validation_type: (validation?.type as FormState["validation_type"] | undefined) ?? "",
    validation_value:
      validation?.type === "substring"
        ? String(validation.value)
        : validation
          ? JSON.stringify(validation.equals)
          : "",
    validation_path: validation?.type === "json_path" ? String(validation.path) : "$.status",
    latency_threshold_ms: config?.latency_threshold_ms != null ? String(config.latency_threshold_ms) : "",
  };
}

export function MonitorForm({
  orgPath,
  base,
  existing,
}: {
  orgPath: string;
  base: string;
  existing?: { monitor: Monitor; url: string };
}) {
  const projects = useLoad<Project[]>(`${orgPath}/projects`);
  const [form, setForm] = useState<FormState>(
    existing ? fromMonitor(existing.monitor, existing.url) : EMPTY_FORM,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set =
    <K extends keyof FormState>(key: K) =>
    (value: FormState[K]) => {
      setForm((f) => ({ ...f, [key]: value }));
    };

  if (projects.error) return <p role="alert" className="error">{projects.error}</p>;
  if (!projects.data) return <p>Loading…</p>;
  if (projects.data.length === 0) {
    return (
      <p>
        Create a project first. <Link to={`${base}/projects`}>Go to projects</Link>
      </p>
    );
  }
  const projectId = form.project_id || projects.data[0]?.id || "";

  return (
    <form
      className="card wide"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        const payload = toPayload({ ...form, project_id: projectId });
        const request = existing
          ? apiRequest<Monitor>("PATCH", `${orgPath}/monitors/${existing.monitor.id}`, {
              ...payload,
              version: existing.monitor.version,
            })
          : apiRequest<Monitor>("POST", `${orgPath}/monitors`, payload);
        request.then(
          (monitor) => {
            navigate(`${base}/monitors/${monitor.id}`);
          },
          (err: unknown) => {
            setError(errorMessage(err));
            setBusy(false);
          },
        );
      }}
    >
      <h1>{existing ? "Edit monitor" : "New monitor"}</h1>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <Field label="Name" value={form.name} onChange={set("name")} />
      <label className="field">
        <span>Project</span>
        <select
          value={projectId}
          onChange={(event) => {
            set("project_id")(event.target.value);
          }}
        >
          {projects.data.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <Field label="URL (http or https, ports 80/443, verified domain)" value={form.url} onChange={set("url")} />
      <label className="field">
        <span>Method</span>
        <select
          value={form.method}
          onChange={(event) => {
            set("method")(event.target.value as FormState["method"]);
          }}
        >
          <option value="GET">GET</option>
          <option value="HEAD">HEAD</option>
        </select>
      </label>
      <label className="field">
        <span>Check every</span>
        <select
          value={form.interval_seconds}
          onChange={(event) => {
            set("interval_seconds")(event.target.value);
          }}
        >
          <option value="60">1 minute</option>
          <option value="120">2 minutes</option>
          <option value="300">5 minutes</option>
        </select>
      </label>
      <Field label="Timeout (seconds, 3-15)" type="number" value={form.timeout_seconds} onChange={set("timeout_seconds")} />
      <Field label="Retries on network errors (0-2)" type="number" value={form.retry_attempts} onChange={set("retry_attempts")} />
      <Field label="Expected status (e.g. 200-299, 301)" value={form.expected_status} onChange={set("expected_status")} />
      <Field
        label="Slow above (ms, optional)"
        type="number"
        value={form.latency_threshold_ms}
        onChange={set("latency_threshold_ms")}
      />
      <label className="field">
        <span>Response validation (GET only)</span>
        <select
          value={form.validation_type}
          onChange={(event) => {
            set("validation_type")(event.target.value as FormState["validation_type"]);
          }}
        >
          <option value="">None</option>
          <option value="substring">Body contains text</option>
          <option value="json_path">JSON field equals</option>
        </select>
      </label>
      {form.validation_type === "json_path" && (
        <Field label="JSON path" value={form.validation_path} onChange={set("validation_path")} />
      )}
      {form.validation_type !== "" && (
        <Field
          label={form.validation_type === "substring" ? "Text" : "Expected value (JSON)"}
          value={form.validation_value}
          onChange={set("validation_value")}
        />
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Saving…" : existing ? "Save changes" : "Create monitor"}
      </button>
    </form>
  );
}

export function MonitorEdit({ orgPath, base, id }: { orgPath: string; base: string; id: string }) {
  const { data, error } = useLoad<{ url: string; monitor: Monitor }>(`${orgPath}/monitors/${id}/edit`);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return <MonitorForm orgPath={orgPath} base={base} existing={data} />;
}

function HeaderEditor({ path, count, onSaved }: { path: string; count: number; onSaved: () => void }) {
  const [rows, setRows] = useState<{ name: string; value: string }[]>([]);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!editing) {
    return (
      <p>
        Custom headers: {count} set (values are write-only and never shown).{" "}
        <button
          type="button"
          onClick={() => {
            setRows([{ name: "", value: "" }]);
            setEditing(true);
          }}
        >
          Replace headers
        </button>
      </p>
    );
  }
  return (
    <form
      className="card wide"
      onSubmit={(event) => {
        event.preventDefault();
        const headers = rows.filter((r) => r.name.trim() !== "");
        apiRequest("PUT", `${path}/headers`, { headers }).then(
          () => {
            setRows([]);
            setEditing(false);
            setError(null);
            onSaved();
          },
          (err: unknown) => {
            setError(errorMessage(err));
          },
        );
      }}
    >
      <h2>Replace custom headers</h2>
      <p className="hint">Up to 5. Saving replaces all existing headers; leave empty to clear them.</p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {rows.map((row, index) => (
        <div className="inline-form" key={index}>
          <Field
            label={`Header ${String(index + 1)} name`}
            value={row.name}
            onChange={(name) => {
              setRows((r) => r.map((x, i) => (i === index ? { ...x, name } : x)));
            }}
          />
          <Field
            label={`Header ${String(index + 1)} value`}
            type="password"
            value={row.value}
            onChange={(value) => {
              setRows((r) => r.map((x, i) => (i === index ? { ...x, value } : x)));
            }}
          />
        </div>
      ))}
      {rows.length < 5 && (
        <button
          type="button"
          onClick={() => {
            setRows((r) => [...r, { name: "", value: "" }]);
          }}
        >
          Add header
        </button>
      )}
      <button type="submit">Save headers</button>
    </form>
  );
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? null;
}

function MonitorAvailability({ orgPath, monitorId }: { orgPath: string; monitorId: string }) {
  const { data, error } = useLoad<Availability>(`${orgPath}/reports/monitors/${monitorId}/availability`);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return null;
  return (
    <>
      <h2>Availability</h2>
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Period</th>
            <th>Uptime</th>
            <th>Coverage</th>
            <th>p50</th>
            <th>p95</th>
          </tr>
        </thead>
        <tbody>
          {(["24h", "7d", "30d"] as const).map((key) => {
            const s = data.periods[key];
            if (!s) return null;
            return (
              <tr key={key}>
                <td>{key}</td>
                <td>{pct(s.uptime_pct, 3)}</td>
                <td>{pct(s.coverage_pct)}</td>
                <td>{s.latency_p50_ms != null ? `${String(s.latency_p50_ms)} ms` : "—"}</td>
                <td>{s.latency_p95_ms != null ? `${String(s.latency_p95_ms)} ms` : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

export function MonitorDetail({
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
  const path = `${orgPath}/monitors/${id}`;
  const monitor = useLoad<Monitor>(path);
  const history = useLoad<Measurement[]>(`${path}/measurements?limit=100`);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = (action: () => Promise<unknown>, success: string) => {
    setMessage(null);
    setError(null);
    action().then(
      () => {
        setMessage(success);
        monitor.reload();
        history.reload();
      },
      (err: unknown) => {
        setError(errorMessage(err));
      },
    );
  };

  if (monitor.error) return <p role="alert" className="error">{monitor.error}</p>;
  if (!monitor.data) return <p>Loading…</p>;
  const m = monitor.data;
  const manage = can(role, "MON.manage");
  const timings = (history.data ?? [])
    .map((x) => x.elapsed_ms)
    .filter((x): x is number => x !== null);
  const p50 = percentile(timings, 50);
  const p95 = percentile(timings, 95);

  return (
    <section>
      <p>
        <Link to={`${base}/monitors`}>← Monitors</Link>
      </p>
      <h1>{m.name}</h1>
      <p className="muted">
        {m.config?.display_url ?? m.hostname} · {statusOf(m)}
      </p>
      <Banner message={message} error={error} />
      {m.lifecycle === "DRAFT" && (
        <p className="hint">
          This monitor starts once its domain is verified. <Link to={`${base}/domains`}>Verify a domain</Link>
        </p>
      )}
      <div className="inline-form">
        {manage && m.lifecycle !== "ARCHIVED" && (
          <Link to={`${base}/monitors/${m.id}/edit`}>Edit</Link>
        )}
        {manage && (m.lifecycle === "ACTIVE" || m.lifecycle === "DRAFT") && (
          <button type="button" onClick={() => { run(() => apiRequest("POST", `${path}/pause`), "Monitor paused."); }}>
            Pause
          </button>
        )}
        {manage && m.lifecycle === "PAUSED" && (
          <button type="button" onClick={() => { run(() => apiRequest("POST", `${path}/resume`), "Monitor resumed."); }}>
            Resume
          </button>
        )}
        {can(role, "MON.check_now") && m.lifecycle === "ACTIVE" && (
          <button
            type="button"
            onClick={() => {
              run(() => apiRequest("POST", `${path}/check-now`), "Check queued; results appear shortly.");
            }}
          >
            Check now
          </button>
        )}
        {manage && m.lifecycle !== "ARCHIVED" && (
          <button
            type="button"
            className="danger"
            onClick={() => {
              if (window.confirm(`Archive ${m.name}? Checks stop; history is kept.`)) {
                run(() => apiRequest("POST", `${path}/archive`), "Monitor archived.");
              }
            }}
          >
            Archive
          </button>
        )}
        {manage && m.lifecycle === "ARCHIVED" && (
          <button type="button" onClick={() => { run(() => apiRequest("POST", `${path}/unarchive`), "Monitor restored (paused)."); }}>
            Unarchive
          </button>
        )}
      </div>
      {m.config && (
        <dl className="details">
          <dt>Method</dt>
          <dd>{m.config.method}</dd>
          <dt>Interval</dt>
          <dd>{m.config.interval_seconds} s</dd>
          <dt>Timeout</dt>
          <dd>{m.config.timeout_ms / 1000} s</dd>
          <dt>Expected status</dt>
          <dd>{m.config.expected_status.map(([l, h]) => (l === h ? String(l) : `${String(l)}-${String(h)}`)).join(", ")}</dd>
        </dl>
      )}
      {manage && m.config && m.lifecycle !== "ARCHIVED" && (
        <HeaderEditor
          path={path}
          count={m.config.header_count}
          onSaved={() => {
            setMessage("Headers saved.");
            monitor.reload();
          }}
        />
      )}
      <MonitorAvailability orgPath={orgPath} monitorId={m.id} />
      <MonitorIncidents orgPath={orgPath} base={base} monitorId={m.id} />
      <h2>Recent checks</h2>
      {timings.length > 0 && (
        <div className="stats">
          <div className="stat">
            <span className="stat-value">{p50} ms</span>
            <span>Median response</span>
          </div>
          <div className="stat">
            <span className="stat-value">{p95} ms</span>
            <span>95th percentile</span>
          </div>
        </div>
      )}
      {history.error && <p role="alert" className="error">{history.error}</p>}
      {history.data && history.data.length === 0 && <p>No checks in the last 24 hours.</p>}
      {history.data && history.data.length > 0 && (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Result</th>
              <th>HTTP</th>
              <th>Response time</th>
              <th>Trigger</th>
            </tr>
          </thead>
          <tbody>
            {history.data.map((row) => (
              <tr key={row.id}>
                <td>{formatDate(row.observed_at)}</td>
                <td>
                  {RESULT_LABELS[row.result] ?? row.result}
                  {row.failure_category ? ` (${row.failure_category})` : ""}
                </td>
                <td>{row.http_status ?? "—"}</td>
                <td>{row.elapsed_ms != null ? `${String(row.elapsed_ms)} ms` : "—"}</td>
                <td>{row.trigger === "MANUAL" ? "Manual" : "Scheduled"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
