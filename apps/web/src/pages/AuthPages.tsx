import { useEffect, useState } from "react";
import { apiRequest } from "../api.ts";
import { useAuth } from "../auth-context.ts";
import { Field, Form, Link } from "../components.tsx";
import { errorMessage } from "../format.ts";
import { navigate, takeFragmentToken } from "../router.ts";

const PASSWORD_HINT = "At least 12 characters. Avoid parts of your email address.";

export function LoginPage() {
  const { refresh } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/login", { email, password });
      await refresh();
      navigate("/");
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Form
      title="Sign in"
      onSubmit={submit}
      error={error}
      busy={busy}
      submitLabel="Sign in"
      footer={<Link to="/forgot-password">Forgot your password?</Link>}
    >
      <Field label="Email" type="email" value={email} onChange={setEmail} autoComplete="username" />
      <Field
        label="Password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
      />
    </Form>
  );
}

function useTokenOnce(): string | null {
  const [token] = useState(takeFragmentToken);
  return token;
}

function NewPasswordForm({
  title,
  submitLabel,
  missingTokenMessage,
  submit,
  allowMissingToken = false,
}: {
  title: string;
  submitLabel: string;
  missingTokenMessage: string;
  submit: (token: string, password: string) => Promise<void>;
  allowMissingToken?: boolean;
}) {
  const token = useTokenOnce();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!token && !allowMissingToken) {
    return (
      <div className="card">
        <h1>{title}</h1>
        <p role="alert" className="error">
          {missingTokenMessage}
        </p>
      </div>
    );
  }

  const onSubmit = async () => {
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await submit(token ?? "", password);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Form title={title} onSubmit={onSubmit} error={error} busy={busy} submitLabel={submitLabel}>
      <p className="hint">{PASSWORD_HINT}</p>
      <Field
        label="New password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete="new-password"
      />
      <Field
        label="Confirm password"
        type="password"
        value={confirm}
        onChange={setConfirm}
        autoComplete="new-password"
      />
    </Form>
  );
}

export function ActivatePage() {
  return (
    <NewPasswordForm
      title="Activate your account"
      submitLabel="Set password and activate"
      missingTokenMessage="This activation link is incomplete. Ask your administrator for a new one."
      submit={async (token, password) => {
        await apiRequest("POST", "/api/auth/activate", { token, password });
        navigate("/login?activated=1");
      }}
    />
  );
}

export function ResetPasswordPage() {
  return (
    <NewPasswordForm
      title="Choose a new password"
      submitLabel="Reset password"
      missingTokenMessage="This reset link is incomplete. Request a new one."
      submit={async (token, password) => {
        await apiRequest("POST", "/api/auth/password-reset/confirm", { token, password });
        navigate("/login?reset=1");
      }}
    />
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (sent) {
    return (
      <div className="card">
        <h1>Check your email</h1>
        <p>If an active account exists for that address, a reset link valid for 30 minutes has been sent.</p>
        <Link to="/login">Back to sign in</Link>
      </div>
    );
  }

  return (
    <Form
      title="Reset your password"
      onSubmit={async () => {
        setBusy(true);
        setError(null);
        try {
          await apiRequest("POST", "/api/auth/password-reset/request", { email });
          setSent(true);
        } catch (err) {
          setError(errorMessage(err));
        } finally {
          setBusy(false);
        }
      }}
      error={error}
      busy={busy}
      submitLabel="Send reset link"
      footer={<Link to="/login">Back to sign in</Link>}
    >
      <Field label="Email" type="email" value={email} onChange={setEmail} autoComplete="email" />
    </Form>
  );
}

export function AcceptAdminInvitePage() {
  const { me } = useAuth();
  const [token] = useState(takeFragmentToken);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!token) {
    return (
      <div className="card">
        <h1>Platform administrator invitation</h1>
        <p role="alert" className="error">
          This invitation link is incomplete. Ask for a new invitation.
        </p>
      </div>
    );
  }

  const accept = async (password?: string) => {
    await apiRequest("POST", "/api/auth/platform-invitations/accept", { token, password });
    navigate("/login?invited=1");
  };

  if (me) {
    return (
      <Form
        title="Accept platform administrator role"
        onSubmit={async () => {
          setBusy(true);
          setError(null);
          try {
            await accept();
          } catch (err) {
            setError(errorMessage(err));
          } finally {
            setBusy(false);
          }
        }}
        error={error}
        busy={busy}
        submitLabel={`Accept as ${me.email}`}
      >
        <p className="hint">You will be signed out and asked to sign in again.</p>
      </Form>
    );
  }

  return (
    <NewPasswordForm
      title="Create your administrator account"
      submitLabel="Create account"
      missingTokenMessage=""
      allowMissingToken
      submit={async (_unused, password) => {
        await accept(password);
      }}
    />
  );
}

interface InvitationPreview {
  organization_name: string;
  role: string;
  email: string;
  account_exists: boolean;
}

export function AcceptInvitePage() {
  const { me } = useAuth();
  const [token] = useState(takeFragmentToken);
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) return;
    let active = true;
    apiRequest<InvitationPreview>("POST", "/api/auth/org-invitations/preview", { token }).then(
      (value) => {
        if (active) setPreview(value);
      },
      (err: unknown) => {
        if (active) setError(errorMessage(err));
      },
    );
    return () => {
      active = false;
    };
  }, [token]);

  if (!token) {
    return (
      <div className="card">
        <h1>Organization invitation</h1>
        <p role="alert" className="error">
          This invitation link is incomplete. Ask for a new invitation.
        </p>
      </div>
    );
  }
  if (error && !preview) {
    return (
      <div className="card">
        <h1>Organization invitation</h1>
        <p role="alert" className="error">
          {error}
        </p>
      </div>
    );
  }
  if (!preview) return <p>Loading…</p>;

  const accept = async (password?: string) => {
    await apiRequest("POST", "/api/auth/org-invitations/accept", { token, password });
    if (me) {
      window.location.assign("/"); // reload so every view sees the new membership
    } else {
      navigate("/login?joined=1");
    }
  };
  const title = `Join ${preview.organization_name}`;

  if (!preview.account_exists) {
    return (
      <>
        <p className="card hint">
          You were invited as {preview.role} ({preview.email}). Choose a password to create your
          account.
        </p>
        <NewPasswordForm
          title={title}
          submitLabel="Create account and join"
          missingTokenMessage=""
          allowMissingToken
          submit={async (_unused, password) => {
            await accept(password);
          }}
        />
      </>
    );
  }
  if (!me || me.email.toLowerCase() !== preview.email) {
    return (
      <div className="card">
        <h1>{title}</h1>
        <p>
          Sign in as {preview.email}, then open the invitation link from your email again.
        </p>
        <Link to="/login">Sign in</Link>
      </div>
    );
  }
  return (
    <Form
      title={title}
      onSubmit={async () => {
        setBusy(true);
        setError(null);
        try {
          await accept();
        } catch (err) {
          setError(errorMessage(err));
        } finally {
          setBusy(false);
        }
      }}
      error={error}
      busy={busy}
      submitLabel={`Join as ${preview.role}`}
    >
      <p>Signed in as {me.email}.</p>
    </Form>
  );
}
