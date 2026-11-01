import { useState } from "react";
import {
  apiRequest,
  type Member,
  type Membership,
  type OrgAuditEntry,
  type OrgInvitation,
  type OrgProfile,
  type OrgRole,
  type Project,
} from "../api.ts";
import { Field, Link } from "../components.tsx";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { assignableRoles, can, ROLE_LABELS } from "../permissions.ts";
import { navigate, type OrgSection } from "../router.ts";
import { DomainsPage } from "./DomainPages.tsx";
import { OrgDashboardPanel, ReportsPage } from "./DashboardPages.tsx";
import { IncidentDetailPage, IncidentList } from "./IncidentPages.tsx";
import { NotificationsPage } from "./NotificationPages.tsx";
import { StatusPagesPage } from "./StatusPages.tsx";
import { MonitorDetail, MonitorEdit, MonitorForm, MonitorList } from "./MonitorPages.tsx";


function useAction(reload: () => void) {
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async (action: () => Promise<unknown>, success: string) => {
    setMessage(null);
    setError(null);
    try {
      await action();
      setMessage(success);
      reload();
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  const banner = (
    <>
      {message && <p role="status">{message}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </>
  );
  return { run, banner };
}

export function OrgPicker({ memberships }: { memberships: Membership[] }) {
  if (memberships.length === 0) {
    return (
      <section className="card">
        <h1>No organizations yet</h1>
        <p>You are not a member of any organization. Ask an organization owner for an invitation.</p>
      </section>
    );
  }
  return (
    <section className="card">
      <h1>Choose an organization</h1>
      <ul className="plain">
        {memberships.map((m) => (
          <li key={m.organization_id}>
            <Link to={`/o/${m.slug}`}>{m.name}</Link> · {ROLE_LABELS[m.role]}
            {m.organization_status === "SUSPENDED" ? " · suspended" : ""}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function OrgShell({
  membership,
  section,
  rest = [],
}: {
  membership: Membership;
  section: OrgSection;
  rest?: string[];
}) {
  const base = `/o/${membership.slug}`;
  const role = membership.role;
  if (membership.organization_status === "SUSPENDED") {
    return (
      <p role="alert" className="error">
        {membership.name} is suspended. Contact the platform team.
      </p>
    );
  }
  const orgPath = `/api/orgs/${membership.organization_id}`;
  return (
    <section>
      <nav className="subnav" aria-label="Organization sections">
        <Link to={base}>Overview</Link>
        <Link to={`${base}/monitors`}>Monitors</Link>
        <Link to={`${base}/incidents`}>Incidents</Link>
        {can(role, "NTF.view") && <Link to={`${base}/notifications`}>Notifications</Link>}
        <Link to={`${base}/status-pages`}>Status pages</Link>
        <Link to={`${base}/reports`}>Reports</Link>
        {can(role, "DOM.view") && <Link to={`${base}/domains`}>Domains</Link>}
        <Link to={`${base}/projects`}>Projects</Link>
        <Link to={`${base}/members`}>Members</Link>
        {can(role, "ORG.update") && <Link to={`${base}/settings`}>Settings</Link>}
        {can(role, "ORG.audit.view") && <Link to={`${base}/audit`}>Audit</Link>}
      </nav>
      {section === "" && (
        <>
          <OrgOverview orgPath={orgPath} />
          <OrgDashboardPanel orgPath={orgPath} base={base} role={role} />
        </>
      )}
      {section === "reports" && <ReportsPage orgPath={orgPath} role={role} />}
      {section === "monitors" && rest.length === 0 && (
        <MonitorList orgPath={orgPath} base={base} role={role} />
      )}
      {section === "monitors" && rest[0] === "new" && can(role, "MON.manage") && (
        <MonitorForm orgPath={orgPath} base={base} />
      )}
      {section === "monitors" && rest[0] && rest[0] !== "new" && rest[1] === "edit" && (
        <MonitorEdit orgPath={orgPath} base={base} id={rest[0]} />
      )}
      {section === "monitors" && rest[0] && rest[0] !== "new" && rest.length === 1 && (
        <MonitorDetail orgPath={orgPath} base={base} id={rest[0]} role={role} />
      )}
      {section === "incidents" && rest.length === 0 && (
        <IncidentList orgPath={orgPath} base={base} />
      )}
      {section === "incidents" && rest[0] && rest.length === 1 && (
        <IncidentDetailPage orgPath={orgPath} base={base} id={rest[0]} role={role} />
      )}
      {section === "notifications" && can(role, "NTF.view") && (
        <NotificationsPage orgPath={orgPath} role={role} />
      )}
      {section === "status-pages" && <StatusPagesPage orgPath={orgPath} role={role} />}
      {section === "domains" && <DomainsPage orgPath={orgPath} role={role} />}
      {section === "projects" && <ProjectsPage orgPath={orgPath} role={role} />}
      {section === "members" && <MembersPage orgPath={orgPath} role={role} />}
      {section === "settings" && <OrgSettingsPage orgPath={orgPath} />}
      {section === "audit" && <OrgAuditPage orgPath={orgPath} />}
    </section>
  );
}

function OrgOverview({ orgPath }: { orgPath: string }) {
  const { data, error } = useLoad<OrgProfile>(orgPath);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <>
      <h1>{data.name}</h1>
      <p className="muted">
        Your role: {ROLE_LABELS[data.my_role]} · Time zone: {data.timezone}
      </p>
      <div className="stats">
        <div className="stat">
          <span className="stat-value">{data.member_count}</span>
          <span>Active members</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.project_count}</span>
          <span>Active projects</span>
        </div>
        <div className="stat">
          <span className="stat-value">{data.limits.max_monitors}</span>
          <span>Monitor limit</span>
        </div>
      </div>
    </>
  );
}

function ProjectsPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const [showArchived, setShowArchived] = useState(false);
  const { data, error, reload } = useLoad<Project[]>(
    `${orgPath}/projects?include_archived=${String(showArchived)}`,
  );
  const { run, banner } = useAction(reload);
  const [name, setName] = useState("");
  const manage = can(role, "PRJ.manage");
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <>
      <h1>Projects</h1>
      {banner}
      {manage && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              await apiRequest("POST", `${orgPath}/projects`, { name });
              setName("");
            }, "Project created.");
          }}
        >
          <Field label="New project name" value={name} onChange={setName} />
          <button type="submit">Create project</button>
        </form>
      )}
      <label>
        <input
          type="checkbox"
          checked={showArchived}
          onChange={(event) => {
            setShowArchived(event.target.checked);
          }}
        />{" "}
        Show archived
      </label>
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Created</th>
            <th>Status</th>
            {manage && <th />}
          </tr>
        </thead>
        <tbody>
          {data.map((project) => (
            <tr key={project.id}>
              <td>{project.name}</td>
              <td>{formatDate(project.created_at)}</td>
              <td>{project.archived_at ? "Archived" : "Active"}</td>
              {manage && (
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      const verb = project.archived_at ? "unarchive" : "archive";
                      void run(
                        () => apiRequest("POST", `${orgPath}/projects/${project.id}/${verb}`),
                        `Project ${verb}d.`,
                      );
                    }}
                  >
                    {project.archived_at ? "Unarchive" : "Archive"}
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function MembersPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const members = useLoad<Member[]>(`${orgPath}/members`);
  const canInvite = can(role, "MEM.invite");
  const invitations = useLoad<OrgInvitation[]>(canInvite ? `${orgPath}/invitations` : null);
  const reloadAll = () => {
    members.reload();
    invitations.reload();
  };
  const { run, banner } = useAction(reloadAll);
  const [email, setEmail] = useState("");
  const roles = assignableRoles(role);
  const [inviteRole, setInviteRole] = useState<OrgRole>(roles.at(-1) ?? "VIEWER");

  if (members.error) return <p role="alert" className="error">{members.error}</p>;
  if (!members.data) return <p>Loading…</p>;
  const manageable = (member: Member) => roles.includes(member.role);
  return (
    <>
      <h1>Members</h1>
      {banner}
      {canInvite && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              await apiRequest("POST", `${orgPath}/invitations`, { email, role: inviteRole });
              setEmail("");
            }, "Invitation sent. It expires in 7 days.");
          }}
        >
          <Field label="Invite by email" type="email" value={email} onChange={setEmail} />
          <label className="field">
            <span>Role</span>
            <select
              value={inviteRole}
              onChange={(event) => {
                setInviteRole(event.target.value as OrgRole);
              }}
            >
              {roles.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </label>
          <button type="submit">Send invitation</button>
        </form>
      )}
      <table tabIndex={0}>
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {members.data.map((member) => (
            <tr key={member.user_id}>
              <td>{member.email}</td>
              <td>
                {manageable(member) ? (
                  <select
                    aria-label={`Role for ${member.email}`}
                    value={member.role}
                    onChange={(event) => {
                      void run(
                        () =>
                          apiRequest("PUT", `${orgPath}/members/${member.user_id}/role`, {
                            role: event.target.value,
                          }),
                        "Role updated.",
                      );
                    }}
                  >
                    {roles.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABELS[r]}
                      </option>
                    ))}
                  </select>
                ) : (
                  ROLE_LABELS[member.role]
                )}
              </td>
              <td>{member.status}</td>
              <td>
                {manageable(member) && (
                  <>
                    <button
                      type="button"
                      onClick={() => {
                        const status = member.status === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
                        void run(
                          () =>
                            apiRequest("PUT", `${orgPath}/members/${member.user_id}/status`, {
                              status,
                            }),
                          "Status updated.",
                        );
                      }}
                    >
                      {member.status === "ACTIVE" ? "Suspend" : "Reactivate"}
                    </button>{" "}
                    <button
                      type="button"
                      className="danger"
                      onClick={() => {
                        if (window.confirm(`Remove ${member.email}? Their access ends immediately.`)) {
                          void run(
                            () => apiRequest("DELETE", `${orgPath}/members/${member.user_id}`),
                            "Member removed.",
                          );
                        }
                      }}
                    >
                      Remove
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {canInvite && invitations.data && invitations.data.length > 0 && (
        <>
          <h2>Pending invitations</h2>
          <ul className="plain">
            {invitations.data.map((invitation) => (
              <li key={invitation.id}>
                {invitation.email} ({ROLE_LABELS[invitation.role]}), expires{" "}
                {formatDate(invitation.expires_at)}{" "}
                {roles.includes(invitation.role) && (
                  <button
                    type="button"
                    onClick={() => {
                      void run(
                        () => apiRequest("DELETE", `${orgPath}/invitations/${invitation.id}`),
                        "Invitation revoked.",
                      );
                    }}
                  >
                    Revoke
                  </button>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
      <h2>Leave organization</h2>
      <button
        type="button"
        className="danger"
        onClick={() => {
          if (window.confirm("Leave this organization? You will need a new invitation to return.")) {
            void run(async () => {
              await apiRequest("POST", `${orgPath}/leave`);
              navigate("/");
            }, "You left the organization.");
          }
        }}
      >
        Leave
      </button>
    </>
  );
}

function OrgSettingsPage({ orgPath }: { orgPath: string }) {
  const { data, error, reload } = useLoad<OrgProfile>(orgPath);
  const { run, banner } = useAction(reload);
  const [draft, setDraft] = useState<{ name?: string; timezone?: string }>({});
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <form
      className="card wide"
      onSubmit={(event) => {
        event.preventDefault();
        void run(async () => {
          await apiRequest("PATCH", orgPath, { version: data.version, ...draft });
          setDraft({});
        }, "Settings saved.");
      }}
    >
      <h1>Organization settings</h1>
      {banner}
      <Field
        label="Name"
        value={draft.name ?? data.name}
        onChange={(name) => {
          setDraft((d) => ({ ...d, name }));
        }}
      />
      <Field
        label="Time zone (IANA, e.g. Europe/Berlin)"
        value={draft.timezone ?? data.timezone}
        onChange={(timezone) => {
          setDraft((d) => ({ ...d, timezone }));
        }}
      />
      <button type="submit">Save</button>
    </form>
  );
}

function OrgAuditPage({ orgPath }: { orgPath: string }) {
  const { data, error } = useLoad<OrgAuditEntry[]>(`${orgPath}/audit?limit=100`);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;
  return (
    <>
      <h1>Organization audit history</h1>
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
          {data.map((entry) => (
            <tr key={entry.id}>
              <td>{formatDate(entry.at)}</td>
              <td>{entry.action}</td>
              <td>
                {entry.actor_email ?? "system"}
                {entry.actor_plane === "PLATFORM" ? " (platform)" : ""}
              </td>
              <td>
                <code>{Object.keys(entry.details).length ? JSON.stringify(entry.details) : "—"}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
