import { useState } from "react";
import { apiRequest, type Challenge, type Domain, type DomainExceptionRequest, type OrgRole } from "../api.ts";
import { Field } from "../components.tsx";
import { errorMessage, formatDate } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { can } from "../permissions.ts";

export function DomainsPage({ orgPath, role }: { orgPath: string; role: OrgRole }) {
  const { data, error, reload } = useLoad<Domain[]>(`${orgPath}/domains`);
  const [fqdn, setFqdn] = useState("");
  const [exception, setException] = useState({ fqdn: "", reason: "" });
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const manage = can(role, "DOM.manage");

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
  return (
    <section>
      <h1>Domains</h1>
      <p className="hint">
        Monitors only run for hostnames on a verified domain (subdomains included). Verification never
        permits private or internal network addresses.
      </p>
      {message && <p role="status">{message}</p>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      {challenge && (
        <div className="card wide" aria-label="DNS challenge">
          <h2>Add this DNS record for {challenge.domain.fqdn}</h2>
          <dl className="details">
            <dt>Type</dt>
            <dd>{challenge.record_type}</dd>
            <dt>Name</dt>
            <dd><code>{challenge.record_name}</code></dd>
            <dt>Value</dt>
            <dd><code>{challenge.record_value}</code></dd>
          </dl>
          <p className="hint">
            Copy the value now; it is not shown again (regenerate if lost). Expires{" "}
            {challenge.domain.challenge_expires_at ? formatDate(challenge.domain.challenge_expires_at) : ""}.
          </p>
        </div>
      )}
      {manage && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            setActionError(null);
            apiRequest<Challenge>("POST", `${orgPath}/domains`, { fqdn }).then(
              (value) => {
                setChallenge(value);
                setFqdn("");
                reload();
              },
              (err: unknown) => {
                setActionError(errorMessage(err));
              },
            );
          }}
        >
          <Field label="Domain (e.g. example.com)" value={fqdn} onChange={setFqdn} />
          <button type="submit">Add domain</button>
        </form>
      )}
      {data.length === 0 ? (
        <p>No domains yet.</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Method</th>
              <th>Status</th>
              <th>Valid until</th>
              {manage && <th />}
            </tr>
          </thead>
          <tbody>
            {data.map((domain) => (
              <tr key={domain.id}>
                <td>{domain.fqdn}</td>
                <td>{domain.method === "DNS_TXT" ? "DNS TXT" : "Admin exception"}</td>
                <td>{domain.status}</td>
                <td>{domain.expires_at ? formatDate(domain.expires_at) : "—"}</td>
                {manage && (
                  <td>
                    {domain.method === "DNS_TXT" && ["PENDING", "EXPIRED"].includes(domain.status) && (
                      <button
                        type="button"
                        onClick={() => {
                          run(() => apiRequest("POST", `${orgPath}/domains/${domain.id}/verify`), `${domain.fqdn} verified.`);
                        }}
                      >
                        Verify
                      </button>
                    )}{" "}
                    {domain.status !== "VERIFIED" && domain.method === "DNS_TXT" && (
                      <button
                        type="button"
                        onClick={() => {
                          setActionError(null);
                          apiRequest<Challenge>("POST", `${orgPath}/domains/${domain.id}/challenge`).then(
                            (value) => {
                              setChallenge(value);
                              reload();
                            },
                            (err: unknown) => {
                              setActionError(errorMessage(err));
                            },
                          );
                        }}
                      >
                        New challenge
                      </button>
                    )}{" "}
                    {domain.status !== "REVOKED" && (
                      <button
                        type="button"
                        className="danger"
                        onClick={() => {
                          if (window.confirm(`Revoke ${domain.fqdn}? Its monitors stop at their next check.`)) {
                            run(() => apiRequest("POST", `${orgPath}/domains/${domain.id}/revoke`), "Domain revoked.");
                          }
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {manage && (
        <form
          className="card wide"
          onSubmit={(event) => {
            event.preventDefault();
            run(async () => {
              await apiRequest("POST", `${orgPath}/domains/exception-requests`, exception);
              setException({ fqdn: "", reason: "" });
            }, "Exception requested. A platform administrator will review it.");
          }}
        >
          <h2>Request a verification exception</h2>
          <p className="hint">For hosts where you cannot add DNS records. Reviewed by the platform team.</p>
          <Field label="Domain" value={exception.fqdn} onChange={(v) => { setException((e) => ({ ...e, fqdn: v })); }} />
          <Field label="Reason" value={exception.reason} onChange={(v) => { setException((e) => ({ ...e, reason: v })); }} />
          <button type="submit">Request exception</button>
        </form>
      )}
    </section>
  );
}

export function AdminDomainExceptionsPage() {
  const { data, error, reload } = useLoad<DomainExceptionRequest[]>("/api/admin/domain-exceptions");
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
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
  return (
    <section>
      <h1>Domain exception requests</h1>
      <p className="hint">Approving lets an organization monitor a host without DNS proof. Network policy still applies.</p>
      {message && <p role="status">{message}</p>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      {data.length === 0 ? (
        <p>No pending requests.</p>
      ) : (
        <table tabIndex={0}>
          <thead>
            <tr>
              <th>Organization</th>
              <th>Domain</th>
              <th>Reason</th>
              <th>Requested</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((request) => (
              <tr key={request.id}>
                <td>{request.organization_name}</td>
                <td>{request.fqdn}</td>
                <td>{request.reason}</td>
                <td>{formatDate(request.requested_at)}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      run(() => apiRequest("POST", `/api/admin/domain-exceptions/${request.id}/approve`, { days: 90 }), "Approved for 90 days.");
                    }}
                  >
                    Approve (90 days)
                  </button>{" "}
                  <button
                    type="button"
                    className="danger"
                    onClick={() => {
                      run(() => apiRequest("POST", `/api/admin/domain-exceptions/${request.id}/reject`), "Rejected.");
                    }}
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
