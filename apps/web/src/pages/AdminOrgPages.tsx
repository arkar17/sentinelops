import { useState } from "react";
import { apiRequest, type Limits, type OrgMetadata } from "../api.ts";
import { Field, Link } from "../components.tsx";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";

export function AdminOrganizationsPage() {
  const { data, error, reload } = useLoad<OrgMetadata[]>("/api/admin/organizations");
  const [form, setForm] = useState({ name: "", slug: "", timezone: "UTC", owner_email: "" });
  const [message, setMessage] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  const set = (key: keyof typeof form) => (value: string) => {
    setForm((f) => ({ ...f, [key]: value }));
  };
  return (
    <section>
      <h1>Organizations</h1>
      {message && <p role="status">{message}</p>}
      {formError && <p role="alert" className="error">{formError}</p>}
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          setMessage(null);
          setFormError(null);
          apiRequest("POST", "/api/admin/organizations", form).then(
            () => {
              setForm({ name: "", slug: "", timezone: "UTC", owner_email: "" });
              setMessage("Organization created. The owner invitation was emailed.");
              reload();
            },
            (err: unknown) => {
              setFormError(errorMessage(err));
            },
          );
        }}
      >
        <Field label="Name" value={form.name} onChange={set("name")} />
        <Field label="Slug" value={form.slug} onChange={set("slug")} />
        <Field label="Time zone" value={form.timezone} onChange={set("timezone")} />
        <Field label="Owner email" type="email" value={form.owner_email} onChange={set("owner_email")} />
        <button type="submit">Create organization</button>
      </form>
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Owners</th>
            <th>Members</th>
            <th>Projects</th>
          </tr>
        </thead>
        <tbody>
          {data.map((org) => (
            <tr key={org.id}>
              <td>
                <Link to={`/admin/organizations/${org.id}`}>{org.name}</Link>
              </td>
              <td>{org.status}</td>
              <td>{org.owner_emails.join(", ") || (org.pending_owner_invitation ? "invitation pending" : "none")}</td>
              <td>{org.member_count}</td>
              <td>{org.project_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

const LIMIT_LABELS: [keyof Limits, string][] = [
  ["max_monitors", "Max monitors"],
  ["min_interval_seconds", "Min interval (60, 120 or 300 s)"],
  ["max_status_pages", "Max status pages"],
  ["max_channels", "Max notification channels"],
];

export function AdminOrganizationPage({ id }: { id: string }) {
  const { data, error, reload } = useLoad<OrgMetadata>(`/api/admin/organizations/${id}`);
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [limits, setLimits] = useState<Partial<Record<keyof Limits, string>>>({});

  const run = (action: () => Promise<unknown>, success: string) => {
    setMessage(null);
    setActionError(null);
    action().then(
      () => {
        setMessage(success);
        reload();
      },
      (err: unknown) => {
        setActionError(errorMessage(err));
      },
    );
  };

  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  const base = `/api/admin/organizations/${id}`;
  return (
    <section>
      <p>
        <Link to="/admin/organizations">← Organizations</Link>
      </p>
      <h1>{data.name}</h1>
      <p className="muted">
        {data.slug} · {data.status} · created {formatDate(data.created_at)} · {data.timezone}
      </p>
      <p className="hint">
        Platform view shows metadata only. Organization data requires an invitation from the
        organization.
      </p>
      {message && <p role="status">{message}</p>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      <div className="stats">
        <div className="stat">
          <span className="stat-value">{data.member_count}</span>
          <span>Active members</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.project_count}</span>
          <span>Active projects</span>
        </div>
      </div>
      <p>Owners: {data.owner_emails.join(", ") || "none"}</p>

      <h2>Status</h2>
      {data.status === "ACTIVE" ? (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (window.confirm(`Suspend ${data.name}? Members lose access immediately.`)) {
              run(() => apiRequest("POST", `${base}/suspend`, { reason }), "Organization suspended.");
            }
          }}
        >
          <Field label="Suspension reason" value={reason} onChange={setReason} />
          <button type="submit" className="danger">
            Suspend
          </button>
        </form>
      ) : (
        <>
          <p>Suspended: {data.suspended_reason}</p>
          <button
            type="button"
            onClick={() => {
              run(() => apiRequest("POST", `${base}/activate`), "Organization activated.");
            }}
          >
            Activate
          </button>
        </>
      )}

      <h2>Limits</h2>
      <form
        className="card wide"
        onSubmit={(event) => {
          event.preventDefault();
          const body: Record<string, number | null> = {};
          for (const [key] of LIMIT_LABELS) {
            const raw = limits[key] ?? (data.limit_overrides[key]?.toString() ?? "");
            body[key] = raw.trim() === "" ? null : Number(raw);
          }
          run(() => apiRequest("PUT", `${base}/limits`, body), "Limits saved.");
        }}
      >
        <p className="hint">Leave empty to use the platform default (shown as effective value).</p>
        {LIMIT_LABELS.map(([key, label]) => (
          <Field
            key={key}
            label={`${label} (effective ${String(data.effective_limits[key])})`}
            type="number"
            value={limits[key] ?? data.limit_overrides[key]?.toString() ?? ""}
            onChange={(value) => {
              setLimits((current) => ({ ...current, [key]: value }));
            }}
          />
        ))}
        <button type="submit">Save limits</button>
      </form>

      {data.owner_emails.length === 0 && (
        <>
          <h2>Owner invitation</h2>
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              run(
                () => apiRequest("POST", `${base}/owner-invitations`, { email: ownerEmail }),
                "Owner invitation sent.",
              );
            }}
          >
            <Field label="Owner email" type="email" value={ownerEmail} onChange={setOwnerEmail} />
            <button type="submit">Send owner invitation</button>
          </form>
        </>
      )}
    </section>
  );
}
