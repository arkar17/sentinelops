import { useCallback, useState } from "react";
import type { OrgDashboard, OrgRole, ReportPoint, ReportResponse, ReportStats } from "../api.ts";
import { DistributionBar, LatencyChart, UptimeChart } from "../charts.tsx";
import { Link } from "../components.tsx";
import { formatDate, formatDuration, pct } from "../format.ts";
import { useLoad, useOrgEvents } from "../hooks.ts";
import { can } from "../permissions.ts";

function ms(value: number | null): string {
  return value === null ? "—" : `${String(value)} ms`;
}

function bucketLabel(iso: string, bucket: "hour" | "day", timezone: string): string {
  const options: Intl.DateTimeFormatOptions =
    bucket === "hour"
      ? { hour: "2-digit", minute: "2-digit", timeZone: timezone }
      : { month: "short", day: "numeric", timeZone: timezone };
  return new Date(iso).toLocaleString(undefined, options);
}

function toSeries(points: ReportPoint[], bucket: "hour" | "day", timezone: string) {
  return {
    latency: points.map((p) => ({
      label: bucketLabel(p.bucket_start, bucket, timezone),
      p50: p.latency_p50_ms,
      p95: p.latency_p95_ms,
    })),
    uptime: points.map((p) => ({
      label: bucketLabel(p.bucket_start, bucket, timezone),
      uptime: p.uptime_pct,
      samples: p.conclusive_samples,
    })),
  };
}

function Stat({ value, label }: { value: string | number; label: string }) {
  return (
    <div className="stat">
      <span className="stat-value">{value}</span>
      <span>{label}</span>
    </div>
  );
}

export function CoverageNote({ stats, method }: { stats: ReportStats; method: "exact" | "approximate" }) {
  return (
    <p className="hint">
      Coverage {pct(stats.coverage_pct)}: {stats.conclusive_samples} conclusive of {stats.expected_samples} expected
      checks ({stats.blocked_samples} blocked, {stats.inconclusive_samples} inconclusive, {stats.missed_samples} missed or
      paused — these are coverage gaps, not uptime).{" "}
      {method === "approximate" ? "Latency for older periods combines hourly summaries (approximate)." : ""}
    </p>
  );
}

function LiveBadge({ state }: { state: string }) {
  const text = state === "live" ? "Live" : state === "revoked" ? "Live updates stopped" : "Reconnecting…";
  return (
    <span className="live muted" role="status">
      ● {text}
    </span>
  );
}

export function OrgDashboardPanel({ orgPath, base, role }: { orgPath: string; base: string; role: OrgRole }) {
  const { data, error, reload } = useLoad<OrgDashboard>(`${orgPath}/dashboard`);
  const refresh = useCallback(() => {
    reload();
  }, [reload]);
  const live = useOrgEvents(orgPath, refresh);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p role="status">Loading dashboard…</p>;
  const s = data.summary_24h;
  const series = toSeries(data.series_24h, data.window_24h.bucket, data.window_24h.timezone);
  return (
    <section aria-label="Monitoring dashboard">
      <div className="inline-form">
        <h2>Last 24 hours</h2>
        <LiveBadge state={live} />
      </div>
      {live === "revoked" && (
        <p role="alert" className="error">
          Your access to this organization changed. Reload the page.
        </p>
      )}
      <div className="stats">
        <Stat value={pct(s.uptime_pct, 3)} label="Uptime (24 h)" />
        <Stat value={ms(s.latency_p95_ms)} label="95th percentile response" />
        <Stat value={data.active_incidents_by_severity.CRITICAL ?? 0} label="Critical incidents open" />
        <Stat value={data.active_incidents_by_severity.WARNING ?? 0} label="Warnings open" />
      </div>
      <CoverageNote stats={s} method={data.window_24h.latency_method} />
      <div className="grid-2">
        <DistributionBar
          title="Health of active monitors"
          slices={[
            { key: "UP", label: "Up", value: data.health.UP ?? 0, tone: "good" },
            { key: "DEGRADED", label: "Degraded", value: data.health.DEGRADED ?? 0, tone: "warning" },
            { key: "DOWN", label: "Down", value: data.health.DOWN ?? 0, tone: "critical" },
            { key: "UNKNOWN", label: "Unknown", value: data.health.UNKNOWN ?? 0, tone: "neutral" },
          ]}
        />
        <div>
          <h3>Monitors</h3>
          <p>
            {data.monitors_by_lifecycle.ACTIVE ?? 0} active · {data.monitors_by_lifecycle.PAUSED ?? 0} paused ·{" "}
            {data.monitors_by_lifecycle.DRAFT ?? 0} waiting for verification · {data.monitors_by_lifecycle.ARCHIVED ?? 0}{" "}
            archived
          </p>
          <p>
            Checks (24 h): {data.results_24h.PASS ?? 0} pass · {data.results_24h.SLOW ?? 0} slow ·{" "}
            {data.results_24h.FAIL ?? 0} fail · {data.results_24h.BLOCKED ?? 0} blocked ·{" "}
            {data.results_24h.INCONCLUSIVE ?? 0} inconclusive
          </p>
          <p className="inline-form">
            <Link to={`${base}/monitors`}>Monitors</Link>
            <Link to={`${base}/incidents`}>Incidents</Link>
            {can(role, "NTF.view") && <Link to={`${base}/notifications`}>Notifications</Link>}
            <Link to={`${base}/reports`}>Reports</Link>
          </p>
        </div>
      </div>
      <div className="grid-2">
        <UptimeChart title="Hourly uptime" points={series.uptime} />
        <LatencyChart title="Response time (ms)" points={series.latency} />
      </div>
      <h3>Recent incidents</h3>
      {data.recent_incidents.length === 0 ? (
        <p>No incidents yet.</p>
      ) : (
        <ul className="plain">
          {data.recent_incidents.map((i) => (
            <li key={i.id}>
              <Link to={`${base}/incidents/${i.id}`}>{i.title}</Link> · {i.monitor_name} · {i.severity.toLowerCase()} ·{" "}
              {i.resolved_at ? `recovered ${formatDate(i.resolved_at)}` : `${i.status.toLowerCase()} since ${formatDate(i.opened_at)}`}
            </li>
          ))}
        </ul>
      )}
      <h3>TLS certificates expiring within 30 days</h3>
      {data.tls_expiring.length === 0 ? (
        <p>None.</p>
      ) : (
        <ul className="plain">
          {data.tls_expiring.map((x) => (
            <li key={x.monitor_id}>
              <Link to={`${base}/monitors/${x.monitor_id}`}>{x.monitor_name}</Link> ({x.hostname}) · expires{" "}
              {formatDate(x.expires_at)} · {x.days_remaining} days left
              {x.days_remaining < x.warn_days ? " · below warning threshold" : ""}
            </li>
          ))}
        </ul>
      )}
      <h3>Recent checks</h3>
      {data.recent_checks.length === 0 ? (
        <p>No checks in the last 24 hours.</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Monitor</th>
              <th>Result</th>
              <th>Response</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_checks.map((c) => (
              <tr key={`${c.monitor_id}:${c.observed_at}`}>
                <td>{formatDate(c.observed_at)}</td>
                <td>{c.monitor_name}</td>
                <td>
                  {c.result}
                  {c.failure_category ? ` (${c.failure_category})` : ""}
                  {c.trigger === "MANUAL" ? " · manual" : ""}
                </td>
                <td>
                  {c.http_status ?? "—"} {c.elapsed_ms != null ? `· ${String(c.elapsed_ms)} ms` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

type Period = "24h" | "7d" | "30d" | "custom";

export function ReportsPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const [period, setPeriod] = useState<Period>("7d");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const query = new URLSearchParams({ period });
  if (period === "custom") {
    if (from) query.set("from", from);
    if (to) query.set("to", to);
  }
  const ready = period !== "custom" || (from !== "" && to !== "");
  const { data, error } = useLoad<ReportResponse>(ready ? `${orgPath}/reports?${query.toString()}` : null);
  const series = data ? toSeries(data.series, data.window.bucket, data.window.timezone) : null;
  return (
    <section>
      <h1>Reports</h1>
      <div className="inline-form" role="group" aria-label="Report period">
        <label className="field">
          <span>Period</span>
          <select
            value={period}
            onChange={(event) => {
              setPeriod(event.target.value as Period);
            }}
          >
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="custom">Custom dates</option>
          </select>
        </label>
        {period === "custom" && (
          <>
            <label className="field">
              <span>From</span>
              <input
                type="date"
                value={from}
                onChange={(event) => {
                  setFrom(event.target.value);
                }}
              />
            </label>
            <label className="field">
              <span>To</span>
              <input
                type="date"
                value={to}
                onChange={(event) => {
                  setTo(event.target.value);
                }}
              />
            </label>
          </>
        )}
        {can(role, "RPT.export") && ready && (
          <a href={`${orgPath}/reports/export.csv?${query.toString()}`} download>
            Export CSV
          </a>
        )}
      </div>
      {!ready && <p className="hint">Choose both dates.</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {ready && !data && !error && <p role="status">Loading report…</p>}
      {data && series && (
        <>
          <p className="muted">
            {formatDate(data.window.start)} – {formatDate(data.window.end)} ({data.window.timezone})
          </p>
          <div className="stats">
            <Stat value={pct(data.summary.uptime_pct, 3)} label="Uptime" />
            <Stat value={pct(data.summary.coverage_pct)} label="Coverage" />
            <Stat value={ms(data.summary.latency_p50_ms)} label="Median response" />
            <Stat value={ms(data.summary.latency_p95_ms)} label="95th percentile" />
            <Stat value={data.summary.incidents_opened} label="Incidents opened" />
            <Stat
              value={data.median_resolution_seconds === null ? "—" : formatDuration(data.median_resolution_seconds)}
              label="Median time to resolve"
            />
          </div>
          <CoverageNote stats={data.summary} method={data.window.latency_method} />
          <p className="hint">
            Estimated downtime {formatDuration(data.summary.downtime_estimate_seconds)} (failed checks × interval);
            outage incidents {formatDuration(data.summary.outage_incident_seconds)} (detection to recovery). Both are
            estimates, not exact customer downtime.
          </p>
          <div className="grid-2">
            <UptimeChart title="Uptime by period" points={series.uptime} />
            <LatencyChart title="Response time (ms)" points={series.latency} />
          </div>
          <h2>By monitor</h2>
          {data.monitors.length === 0 ? (
            <p>No monitors.</p>
          ) : (
            <table tabIndex={0}>
              <thead>
                <tr>
                  <th>Monitor</th>
                  <th>Uptime</th>
                  <th>Coverage</th>
                  <th>p50</th>
                  <th>p95</th>
                  <th>Incidents</th>
                  <th>Est. downtime</th>
                </tr>
              </thead>
              <tbody>
                {data.monitors.map((m) => (
                  <tr key={m.monitor_id}>
                    <td>
                      {m.name}
                      <div className="muted">
                        {m.hostname} · {m.project_name}
                      </div>
                    </td>
                    <td>{pct(m.stats.uptime_pct, 3)}</td>
                    <td>{pct(m.stats.coverage_pct)}</td>
                    <td>{ms(m.stats.latency_p50_ms)}</td>
                    <td>{ms(m.stats.latency_p95_ms)}</td>
                    <td>{m.stats.incidents_opened}</td>
                    <td>{formatDuration(m.stats.downtime_estimate_seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data.total_monitors > data.monitors.length && (
            <p className="hint">
              Showing {data.monitors.length} of {data.total_monitors} monitors; export CSV for all.
            </p>
          )}
        </>
      )}
    </section>
  );
}
