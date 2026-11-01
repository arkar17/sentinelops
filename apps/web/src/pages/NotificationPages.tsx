import { useState } from "react";
import {
  apiRequest,
  type DeliveryItem,
  type Member,
  type Monitor,
  type NotificationChannel,
  type NotificationRoute,
  type NotifyEvent,
  type OrgRole,
  type Project,
} from "../api.ts";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { can } from "../permissions.ts";

const EVENT_LABELS: Record<NotifyEvent, string> = {
  INCIDENT_OPENED: "Outage opened",
  TLS_EXPIRY_WARNING: "TLS certificate expiring",
  INCIDENT_ACKNOWLEDGED: "Incident acknowledged",
  INCIDENT_RESOLVED: "Incident resolved",
  MONITOR_AUTO_PAUSED: "Monitor paused by policy",
};
const EVENTS = Object.keys(EVENT_LABELS) as NotifyEvent[];
const STATE_LABELS: Record<string, string> = {
  PENDING: "Queued",
  LEASED: "Sending",
  SENT: "Sent",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
};

function Status({ message, error }: { message: string | null; error: string | null }) {
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

function MemberPicker({
  members,
  selected,
  onChange,
}: {
  members: Member[];
  selected: string[];
  onChange: (ids: string[]) => void;
}) {
  return (
    <fieldset className="field">
      <legend>Recipients (active members)</legend>
      {members.map((m) => (
        <label key={m.user_id}>
          <input
            type="checkbox"
            checked={selected.includes(m.user_id)}
            onChange={(event) => {
              onChange(
                event.target.checked
                  ? [...selected, m.user_id]
                  : selected.filter((id) => id !== m.user_id),
              );
            }}
          />{" "}
          {m.email}
        </label>
      ))}
    </fieldset>
  );
}

function NewChannelForm({
  orgPath,
  members,
  onCreated,
}: {
  orgPath: string;
  members: Member[];
  onCreated: () => void;
}) {
  const [type, setType] = useState<"TELEGRAM" | "EMAIL">("TELEGRAM");
  const [label, setLabel] = useState("");
  const [token, setToken] = useState("");
  const [chat, setChat] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [routeAll, setRouteAll] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = () => {
    setBusy(true);
    setError(null);
    const body =
      type === "TELEGRAM"
        ? { type, label, telegram: { bot_token: token, chat_id: chat }, route_all_events: routeAll }
        : { type, label, recipient_user_ids: recipients, route_all_events: routeAll };
    apiRequest("POST", `${orgPath}/notification-channels`, body)
      .then(() => {
        setLabel("");
        setToken("");
        setChat("");
        setRecipients([]);
        onCreated();
      })
      .catch((err: unknown) => {
        setError(errorMessage(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <form
      className="note-form"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <h2>Add a channel</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <label className="field">
        <span>Type</span>
        <select
          value={type}
          onChange={(event) => {
            setType(event.target.value as "TELEGRAM" | "EMAIL");
          }}
        >
          <option value="TELEGRAM">Telegram</option>
          <option value="EMAIL">Email (team members)</option>
        </select>
      </label>
      <label className="field">
        <span>Label</span>
        <input
          value={label}
          maxLength={80}
          onChange={(event) => {
            setLabel(event.target.value);
          }}
        />
      </label>
      {type === "TELEGRAM" ? (
        <>
          <p className="hint">
            Create a bot with @BotFather, add it to your group or channel, then paste its token and the
            chat ID. Credentials are encrypted and can be replaced but never shown again. Use “Send test”
            to confirm the bot can post.
          </p>
          <label className="field">
            <span>Bot token</span>
            <input
              type="password"
              autoComplete="off"
              value={token}
              onChange={(event) => {
                setToken(event.target.value);
              }}
            />
          </label>
          <label className="field">
            <span>Chat ID</span>
            <input
              autoComplete="off"
              value={chat}
              placeholder="-1001234567890 or @channel"
              onChange={(event) => {
                setChat(event.target.value);
              }}
            />
          </label>
        </>
      ) : (
        <MemberPicker members={members} selected={recipients} onChange={setRecipients} />
      )}
      <label>
        <input
          type="checkbox"
          checked={routeAll}
          onChange={(event) => {
            setRouteAll(event.target.checked);
          }}
        />{" "}
        Send all alert types for every monitor to this channel
      </label>
      <button type="submit" disabled={busy || !label.trim()}>
        {busy ? "Please wait…" : "Add channel"}
      </button>
    </form>
  );
}

function ChannelRow({
  orgPath,
  channel,
  role,
  members,
  onChanged,
}: {
  orgPath: string;
  channel: NotificationChannel;
  role: OrgRole;
  members: Member[];
  onChanged: (message: string | null, error: string | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [token, setToken] = useState("");
  const [chat, setChat] = useState("");
  const [recipients, setRecipients] = useState(channel.recipients.map((r) => r.user_id));
  const path = `${orgPath}/notification-channels/${channel.id}`;
  const manage = can(role, "NTF.channel.manage");
  const run = (method: string, url: string, body: unknown, success: string) => {
    apiRequest(method, url, body).then(
      () => {
        setEditing(false);
        setToken("");
        setChat("");
        onChanged(success, null);
      },
      (err: unknown) => {
        onChanged(null, errorMessage(err));
      },
    );
  };
  return (
    <tr>
      <td>
        <strong>{channel.label}</strong>
        <div className="muted">{channel.type === "TELEGRAM" ? "Telegram" : "Email"}</div>
      </td>
      <td>
        {channel.type === "TELEGRAM"
          ? channel.credentials_set
            ? "Bot token and chat ID set"
            : "Not configured"
          : channel.recipients.map((r) => r.email).join(", ") || "No recipients"}
        {editing && channel.type === "TELEGRAM" && (
          <div className="note-form">
            <label className="field">
              <span>New bot token</span>
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(event) => {
                  setToken(event.target.value);
                }}
              />
            </label>
            <label className="field">
              <span>New chat ID</span>
              <input
                autoComplete="off"
                value={chat}
                onChange={(event) => {
                  setChat(event.target.value);
                }}
              />
            </label>
            <button
              type="button"
              onClick={() => {
                run(
                  "PATCH",
                  path,
                  { version: channel.version, telegram: { bot_token: token, chat_id: chat } },
                  "Credentials replaced.",
                );
              }}
            >
              Save credentials
            </button>
          </div>
        )}
        {editing && channel.type === "EMAIL" && (
          <div className="note-form">
            <MemberPicker members={members} selected={recipients} onChange={setRecipients} />
            <button
              type="button"
              onClick={() => {
                run("PATCH", path, { version: channel.version, recipient_user_ids: recipients }, "Recipients saved.");
              }}
            >
              Save recipients
            </button>
          </div>
        )}
      </td>
      <td>{channel.enabled ? "Enabled" : "Disabled"}</td>
      <td>
        <div className="inline-form">
          {can(role, "NTF.channel.test") && channel.enabled && (
            <button
              type="button"
              onClick={() => {
                run("POST", `${path}/test`, undefined, "Test message queued. Check delivery history below.");
              }}
            >
              Send test
            </button>
          )}
          {manage && (
            <>
              <button
                type="button"
                onClick={() => {
                  setEditing(!editing);
                }}
              >
                {editing ? "Cancel" : channel.type === "TELEGRAM" ? "Replace credentials" : "Edit recipients"}
              </button>
              <button
                type="button"
                className={channel.enabled ? "danger" : ""}
                onClick={() => {
                  run(
                    "PATCH",
                    path,
                    { version: channel.version, enabled: !channel.enabled },
                    channel.enabled ? "Channel disabled; queued alerts were cancelled." : "Channel enabled.",
                  );
                }}
              >
                {channel.enabled ? "Disable" : "Enable"}
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

function RouteSection({
  orgPath,
  role,
  channels,
}: {
  orgPath: string;
  role: OrgRole;
  channels: NotificationChannel[];
}) {
  const routes = useLoad<NotificationRoute[]>(`${orgPath}/notification-routes`);
  const projects = useLoad<Project[]>(`${orgPath}/projects`);
  const monitors = useLoad<Monitor[]>(`${orgPath}/monitors`);
  const [channelId, setChannelId] = useState("");
  const [scope, setScope] = useState("");
  const [events, setEvents] = useState<NotifyEvent[]>(["INCIDENT_OPENED", "INCIDENT_RESOLVED"]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const manage = can(role, "NTF.route.manage");
  const label = (id: string) => channels.find((c) => c.id === id)?.label ?? "Channel";
  const scopeLabel = (r: NotificationRoute) => {
    if (r.monitor_id) return `Monitor: ${monitors.data?.find((m) => m.id === r.monitor_id)?.name ?? "—"}`;
    if (r.project_id) return `Project: ${projects.data?.find((p) => p.id === r.project_id)?.name ?? "—"}`;
    return "All monitors";
  };
  const run = (method: string, url: string, body: unknown, success: string) => {
    setMessage(null);
    setError(null);
    apiRequest(method, url, body).then(
      () => {
        setMessage(success);
        routes.reload();
      },
      (err: unknown) => {
        setError(errorMessage(err));
      },
    );
  };
  return (
    <section>
      <h2>Routes</h2>
      <p className="hint">Routes decide which alerts go to which channel.</p>
      <Status message={message} error={error} />
      {routes.data && routes.data.length === 0 && <p>No routes yet. Alerts are not sent until a route exists.</p>}
      {routes.data && routes.data.length > 0 && (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Channel</th>
              <th>Scope</th>
              <th>Events</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {routes.data.map((r) => (
              <tr key={r.id}>
                <td>{label(r.channel_id)}</td>
                <td>{scopeLabel(r)}</td>
                <td>{r.event_types.map((e) => EVENT_LABELS[e]).join(", ")}</td>
                <td>
                  {manage && (
                    <button
                      type="button"
                      className="danger"
                      onClick={() => {
                        run("DELETE", `${orgPath}/notification-routes/${r.id}`, undefined, "Route removed.");
                      }}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {manage && channels.length > 0 && (
        <form
          className="note-form"
          onSubmit={(event) => {
            event.preventDefault();
            const [kind, id] = scope.split(":");
            run(
              "POST",
              `${orgPath}/notification-routes`,
              {
                channel_id: channelId,
                project_id: kind === "project" ? id : null,
                monitor_id: kind === "monitor" ? id : null,
                event_types: events,
              },
              "Route added.",
            );
          }}
        >
          <h3>Add a route</h3>
          <label className="field">
            <span>Channel</span>
            <select
              value={channelId}
              onChange={(event) => {
                setChannelId(event.target.value);
              }}
            >
              <option value="">Choose a channel…</option>
              {channels.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Scope</span>
            <select
              value={scope}
              onChange={(event) => {
                setScope(event.target.value);
              }}
            >
              <option value="">All monitors</option>
              {(projects.data ?? []).map((p) => (
                <option key={p.id} value={`project:${p.id}`}>
                  Project: {p.name}
                </option>
              ))}
              {(monitors.data ?? []).map((m) => (
                <option key={m.id} value={`monitor:${m.id}`}>
                  Monitor: {m.name}
                </option>
              ))}
            </select>
          </label>
          <fieldset className="field">
            <legend>Events</legend>
            {EVENTS.map((e) => (
              <label key={e}>
                <input
                  type="checkbox"
                  checked={events.includes(e)}
                  onChange={(event) => {
                    setEvents(event.target.checked ? [...events, e] : events.filter((x) => x !== e));
                  }}
                />{" "}
                {EVENT_LABELS[e]}
              </label>
            ))}
          </fieldset>
          <button type="submit" disabled={!channelId || events.length === 0}>
            Add route
          </button>
        </form>
      )}
    </section>
  );
}

function DeliveryHistory({ orgPath, channels }: { orgPath: string; channels: NotificationChannel[] }) {
  const { data, error } = useLoad<DeliveryItem[]>(`${orgPath}/notification-deliveries?limit=50`);
  const label = (id: string) => channels.find((c) => c.id === id)?.label ?? "Channel";
  return (
    <section>
      <h2>Delivery history</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {data && data.length === 0 && <p>No notifications yet.</p>}
      {data && data.length > 0 && (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Queued</th>
              <th>Channel</th>
              <th>Event</th>
              <th>Status</th>
              <th>Attempts</th>
              <th>Last result</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.id} data-state={d.state}>
                <td>{formatDate(d.created_at)}</td>
                <td>{label(d.channel_id)}</td>
                <td>
                  {d.event_type === "CHANNEL_TEST" ? "Test" : (EVENT_LABELS[d.event_type as NotifyEvent] ?? d.event_type)}
                </td>
                <td>
                  {STATE_LABELS[d.state] ?? d.state}
                  {d.cancel_reason ? ` (${d.cancel_reason})` : ""}
                  {d.state === "PENDING" && d.attempts > 0 ? ` · retry ${formatDate(d.next_attempt_at)}` : ""}
                </td>
                <td>{d.attempts}</td>
                <td>{d.last_result_code ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function NotificationsPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const channels = useLoad<NotificationChannel[]>(`${orgPath}/notification-channels`);
  const members = useLoad<Member[]>(`${orgPath}/members`);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const active = (members.data ?? []).filter((m) => m.status === "ACTIVE");
  if (channels.error) return <p role="alert" className="error">{channels.error}</p>;
  if (!channels.data) return <p role="status">Loading…</p>;
  const list = channels.data;
  return (
    <section>
      <h1>Notifications</h1>
      <Status message={message} error={error} />
      {list.length === 0 ? (
        <p>No channels yet.{can(role, "NTF.channel.manage") ? " Add Telegram or email below." : ""}</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Channel</th>
              <th>Destination</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.map((c) => (
              <ChannelRow
                key={`${c.id}:${String(c.version)}`}
                orgPath={orgPath}
                channel={c}
                role={role}
                members={active}
                onChanged={(ok, err) => {
                  setMessage(ok);
                  setError(err);
                  channels.reload();
                }}
              />
            ))}
          </tbody>
        </table>
      )}
      {can(role, "NTF.channel.manage") && (
        <NewChannelForm
          orgPath={orgPath}
          members={active}
          onCreated={() => {
            setMessage("Channel added.");
            setError(null);
            channels.reload();
          }}
        />
      )}
      <RouteSection key={list.length} orgPath={orgPath} role={role} channels={list} />
      {can(role, "NTF.delivery.view") && <DeliveryHistory orgPath={orgPath} channels={list} />}
    </section>
  );
}
