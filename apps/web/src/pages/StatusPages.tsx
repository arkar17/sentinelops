import { useState } from "react";
import {
  apiRequest,
  type Monitor,
  type OrgRole,
  type PublicStatus,
  type PublicStatusPage as PublicPayload,
  type StatusPageConfig,
} from "../api.ts";
import { Link } from "../components.tsx";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { can } from "../permissions.ts";

const PUBLIC_LABELS: Record<PublicStatus, string> = {
  OPERATIONAL: "Operational",
  DEGRADED: "Degraded performance",
  OUTAGE: "Outage",
  UNKNOWN: "Status unknown",
};
const OVERALL_LABELS: Record<PublicStatus, string> = {
  OPERATIONAL: "All systems operational",
  DEGRADED: "Some systems are degraded",
  OUTAGE: "Some systems are experiencing an outage",
  UNKNOWN: "Status is currently unknown",
};

interface Selection {
  monitor_id: string;
  public_display_name: string;
}

function MonitorSelector({
  monitors,
  selected,
  onChange,
}: {
  monitors: Monitor[];
  selected: Selection[];
  onChange: (value: Selection[]) => void;
}) {
  return (
    <fieldset className="field">
      <legend>Monitors shown (public names only; hosts and URLs are never published)</legend>
      {monitors.map((m) => {
        const current = selected.find((s) => s.monitor_id === m.id);
        return (
          <div key={m.id} className="inline-form">
            <label>
              <input
                type="checkbox"
                checked={Boolean(current)}
                onChange={(event) => {
                  onChange(
                    event.target.checked
                      ? [...selected, { monitor_id: m.id, public_display_name: m.name }]
                      : selected.filter((s) => s.monitor_id !== m.id),
                  );
                }}
              />{" "}
              {m.name}
            </label>
            {current && (
              <label className="field">
                <span>Public name for {m.name}</span>
                <input
                  value={current.public_display_name}
                  maxLength={80}
                  onChange={(event) => {
                    onChange(
                      selected.map((s) =>
                        s.monitor_id === m.id ? { ...s, public_display_name: event.target.value } : s,
                      ),
                    );
                  }}
                />
              </label>
            )}
          </div>
        );
      })}
    </fieldset>
  );
}

function PageEditor({
  orgPath,
  monitors,
  page,
  onSaved,
}: {
  orgPath: string;
  monitors: Monitor[];
  page: StatusPageConfig | undefined;
  onSaved: (message: string) => void;
}) {
  const [title, setTitle] = useState(page?.title ?? "");
  const [slug, setSlug] = useState(page?.public_slug ?? "");
  const [selected, setSelected] = useState<Selection[]>(
    page?.monitors.map((m) => ({ monitor_id: m.monitor_id, public_display_name: m.public_display_name })) ?? [],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      className="note-form"
      onSubmit={(event) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        const request = page
          ? apiRequest("PATCH", `${orgPath}/status-pages/${page.id}`, {
              version: page.version,
              title,
              public_slug: slug,
              monitors: selected,
            })
          : apiRequest("POST", `${orgPath}/status-pages`, { title, public_slug: slug, monitors: selected });
        request
          .then(() => {
            onSaved(page ? "Status page saved." : "Status page created. It stays private until published.");
            if (!page) {
              setTitle("");
              setSlug("");
              setSelected([]);
            }
          })
          .catch((err: unknown) => {
            setError(errorMessage(err));
          })
          .finally(() => {
            setBusy(false);
          });
      }}
    >
      <h2>{page ? `Edit ${page.title}` : "New status page"}</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <label className="field">
        <span>Title</span>
        <input
          value={title}
          maxLength={80}
          onChange={(event) => {
            setTitle(event.target.value);
          }}
        />
      </label>
      <label className="field">
        <span>Public address</span>
        <input
          value={slug}
          maxLength={40}
          placeholder="acme-status"
          onChange={(event) => {
            setSlug(event.target.value.toLowerCase());
          }}
        />
      </label>
      <MonitorSelector monitors={monitors} selected={selected} onChange={setSelected} />
      <button type="submit" disabled={busy || !title.trim() || !slug.trim()}>
        {busy ? "Please wait…" : page ? "Save page" : "Create page"}
      </button>
    </form>
  );
}

export function StatusPagesPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const pages = useLoad<StatusPageConfig[]>(`${orgPath}/status-pages`);
  const monitors = useLoad<Monitor[]>(can(role, "STP.manage") ? `${orgPath}/monitors` : null);
  const [editing, setEditing] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (pages.error) return <p role="alert" className="error">{pages.error}</p>;
  if (!pages.data) return <p role="status">Loading…</p>;
  const toggle = (page: StatusPageConfig) => {
    setMessage(null);
    setError(null);
    apiRequest("POST", `${orgPath}/status-pages/${page.id}/${page.published ? "unpublish" : "publish"}`).then(
      () => {
        setMessage(page.published ? "Page unpublished; the public address now returns not found." : "Page published.");
        pages.reload();
      },
      (err: unknown) => {
        setError(errorMessage(err));
      },
    );
  };
  return (
    <section>
      <h1>Status pages</h1>
      {message && <p role="status">{message}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {pages.data.length === 0 && <p>No status pages yet.</p>}
      {pages.data.length > 0 && (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Page</th>
              <th>Monitors</th>
              <th>Visibility</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {pages.data.map((page) => (
              <tr key={page.id}>
                <td>
                  <strong>{page.title}</strong>
                  <div className="muted">/status/{page.public_slug}</div>
                </td>
                <td>{page.monitors.map((m) => m.public_display_name).join(", ") || "None"}</td>
                <td>
                  {page.published ? <Link to={`/status/${page.public_slug}`}>Published</Link> : "Private"}
                </td>
                <td>
                  <div className="inline-form">
                    {can(role, "STP.publish") && (
                      <button
                        type="button"
                        onClick={() => {
                          toggle(page);
                        }}
                      >
                        {page.published ? "Unpublish" : "Publish"}
                      </button>
                    )}
                    {can(role, "STP.manage") && (
                      <button
                        type="button"
                        onClick={() => {
                          setEditing(editing === page.id ? null : page.id);
                        }}
                      >
                        {editing === page.id ? "Close" : "Edit"}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {can(role, "STP.manage") && monitors.data && (
        <PageEditor
          key={editing ?? "new"}
          orgPath={orgPath}
          monitors={monitors.data.filter((m) => m.lifecycle !== "ARCHIVED")}
          page={pages.data.find((p) => p.id === editing)}
          onSaved={(text) => {
            setMessage(text);
            setEditing(null);
            pages.reload();
          }}
        />
      )}
    </section>
  );
}

function uptime(value: number | null): string {
  return value === null ? "—" : `${value.toFixed(2)}%`;
}

/** Anonymous page rendered from the sanitized public snapshot. All text renders escaped. */
export function PublicStatusPage({ slug }: { slug: string }) {
  const { data, error } = useLoad<PublicPayload>(`/api/status/${slug}`);
  if (error) {
    return (
      <p role="alert" className="error">
        This status page is not available.
      </p>
    );
  }
  if (!data) return <p role="status">Loading…</p>;
  return (
    <section className="public-status">
      <h1>{data.title}</h1>
      <p className="overall" data-status={data.overall}>
        {OVERALL_LABELS[data.overall]}
      </p>
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Service</th>
            <th>Status</th>
            <th>Last 24 h</th>
            <th>Last 7 days</th>
          </tr>
        </thead>
        <tbody>
          {data.components.map((c) => (
            <tr key={c.name} data-status={c.status}>
              <td>{c.name}</td>
              <td>{PUBLIC_LABELS[c.status]}</td>
              <td>{uptime(c.uptime_24h)}</td>
              <td>{uptime(c.uptime_7d)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Current incidents</h2>
      {data.active_incidents.length === 0 ? (
        <p>No current incidents.</p>
      ) : (
        <ul className="plain">
          {data.active_incidents.map((i) => (
            <li key={`${i.component}:${i.started_at}`}>
              <strong>{i.title}</strong> · {i.component} · {i.status === "INVESTIGATING" ? "Investigating" : "Acknowledged"}{" "}
              · since {formatDate(i.started_at)}
            </li>
          ))}
        </ul>
      )}
      <h2>Past 7 days</h2>
      {data.recent_incidents.length === 0 ? (
        <p>No incidents in the past 7 days.</p>
      ) : (
        <ul className="plain">
          {data.recent_incidents.map((i) => (
            <li key={`${i.component}:${i.started_at}`}>
              <strong>{i.title}</strong> · {i.component} · {formatDate(i.started_at)}
              {i.resolved_at ? ` – resolved ${formatDate(i.resolved_at)}` : ""}
            </li>
          ))}
        </ul>
      )}
      <p className="muted">Updated {formatDate(data.generated_at)}. Availability is measured by scheduled checks.</p>
    </section>
  );
}
