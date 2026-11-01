import { useState } from "react";
import { apiRequest } from "../api.ts";
import { useAuth } from "../auth-context.ts";
import { Field, Form } from "../components.tsx";
import { errorMessage } from "../format.ts";
import { useLoad } from "../hooks.ts";
import { navigate } from "../router.ts";

interface MfaStatus {
  enabled: boolean;
  required: boolean;
  pending: string | null;
  recovery_codes_left: number;
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <section className="card wide" aria-labelledby="recovery-heading">
      <h1 id="recovery-heading">Save your recovery codes</h1>
      <p>
        Each code signs you in once if you lose your authenticator. They are shown only now; store them somewhere
        safe and offline.
      </p>
      <ul className="plain codes" aria-label="Recovery codes">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ul>
      <button type="button" onClick={onDone}>
        I have saved these codes
      </button>
    </section>
  );
}

/** Two steps: re-enter the password, then confirm a code from the authenticator app. */
export function MfaEnrollForm({ onEnabled }: { onEnabled: () => void }) {
  const { refresh } = useAuth();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (codes) {
    return (
      <RecoveryCodes
        codes={codes}
        onDone={() => {
          void refresh().then(onEnabled);
        }}
      />
    );
  }
  if (!secret) {
    return (
      <Form
        title="Set up multi-factor authentication"
        submitLabel="Continue"
        error={error}
        busy={busy}
        onSubmit={() =>
          run(async () => {
            setSecret(await apiRequest("POST", "/api/auth/mfa/enroll", { current_password: password }));
            setPassword("");
          })
        }
      >
        <p>Confirm your password to add an authenticator app (any standard TOTP app).</p>
        <Field label="Current password" type="password" value={password} onChange={setPassword} autoComplete="current-password" />
      </Form>
    );
  }
  return (
    <Form
      title="Add the account to your authenticator"
      submitLabel="Turn on MFA"
      error={error}
      busy={busy}
      onSubmit={() =>
        run(async () => {
          const result = await apiRequest<{ recovery_codes: string[] }>("POST", "/api/auth/mfa/enroll/confirm", { code });
          setCodes(result.recovery_codes);
          setSecret(null);
        })
      }
    >
      <p>
        Enter this setup key in your authenticator app, or open the link on a device that has one. It is shown only
        once.
      </p>
      <p>
        <code aria-label="Setup key" data-testid="mfa-secret">
          {secret.secret}
        </code>
      </p>
      <p>
        <a href={secret.otpauth_uri}>Open in authenticator app</a>
      </p>
      <Field label="Authentication code" value={code} onChange={setCode} autoComplete="one-time-code" />
    </Form>
  );
}

export function MfaVerifyPage() {
  const { refresh, logout } = useAuth();
  const [value, setValue] = useState("");
  const [recovery, setRecovery] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/mfa/verify", recovery ? { recovery_code: value } : { code: value });
      await refresh();
      navigate("/admin");
    } catch (err) {
      setError(errorMessage(err));
      setValue("");
      await refresh(); // the session ends after repeated failures
    } finally {
      setBusy(false);
    }
  };
  return (
    <Form
      title="Two-step verification"
      submitLabel="Verify"
      error={error}
      busy={busy}
      onSubmit={submit}
      footer={
        <p className="inline-form">
          <button
            type="button"
            onClick={() => {
              setRecovery(!recovery);
              setValue("");
            }}
          >
            {recovery ? "Use an authentication code" : "Use a recovery code"}
          </button>
          <button
            type="button"
            onClick={() => {
              void logout().then(() => {
                navigate("/login");
              });
            }}
          >
            Sign out
          </button>
        </p>
      }
    >
      <Field
        label={recovery ? "Recovery code" : "Authentication code"}
        value={value}
        onChange={setValue}
        autoComplete="one-time-code"
      />
    </Form>
  );
}

export function MfaEnrollPage() {
  return (
    <>
      <p role="status" className="hint">
        Platform administrators must use multi-factor authentication before continuing.
      </p>
      <MfaEnrollForm
        onEnabled={() => {
          navigate("/admin");
        }}
      />
    </>
  );
}

export function AdminSecurityPage() {
  const { data, error, reload } = useLoad<MfaStatus>("/api/auth/mfa");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p role="status">Loading…</p>;
  if (codes) {
    return (
      <RecoveryCodes
        codes={codes}
        onDone={() => {
          setCodes(null);
          reload();
        }}
      />
    );
  }
  if (!data.enabled) {
    return (
      <section>
        <h1>Security</h1>
        <p>Multi-factor authentication is off{data.required ? " but required" : ""}.</p>
        <MfaEnrollForm onEnabled={reload} />
      </section>
    );
  }
  const act = (path: string, success: string) => {
    setMessage(null);
    setActionError(null);
    apiRequest<{ recovery_codes?: string[] } | undefined>("POST", path, { current_password: password, code }).then(
      (result) => {
        setPassword("");
        setCode("");
        if (result?.recovery_codes) setCodes(result.recovery_codes);
        else setMessage(success);
        reload();
      },
      (err: unknown) => {
        setActionError(errorMessage(err));
      },
    );
  };
  return (
    <section>
      <h1>Security</h1>
      <p>
        Multi-factor authentication is on. {data.recovery_codes_left} recovery codes left.
        {data.required ? " It is required for platform administrators." : ""}
      </p>
      {message && <p role="status">{message}</p>}
      {actionError && (
        <p role="alert" className="error">
          {actionError}
        </p>
      )}
      <div className="note-form">
        <Field label="Current password" type="password" value={password} onChange={setPassword} autoComplete="current-password" />
        <Field label="Authentication code" value={code} onChange={setCode} autoComplete="one-time-code" />
        <div className="inline-form">
          <button
            type="button"
            onClick={() => {
              act("/api/auth/mfa/recovery-codes", "Recovery codes replaced.");
            }}
          >
            Replace recovery codes
          </button>
          {!data.required && (
            <button
              type="button"
              className="danger"
              onClick={() => {
                act("/api/auth/mfa/disable", "Multi-factor authentication turned off.");
              }}
            >
              Turn off MFA
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
