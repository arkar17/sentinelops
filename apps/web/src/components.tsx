import type { FormEvent, ReactNode } from "react";
import { navigate } from "./router.ts";

export function Link({ to, children }: { to: string; children: ReactNode }) {
  return (
    <a
      href={to}
      onClick={(event) => {
        event.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export function Form({
  title,
  onSubmit,
  error,
  busy,
  submitLabel,
  children,
  footer,
}: {
  title: string;
  onSubmit: () => Promise<void>;
  error: string | null;
  busy: boolean;
  submitLabel: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const handle = (event: FormEvent) => {
    event.preventDefault();
    void onSubmit();
  };
  return (
    <form className="card" onSubmit={handle} noValidate>
      <h1>{title}</h1>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {children}
      <button type="submit" disabled={busy}>
        {busy ? "Please wait…" : submitLabel}
      </button>
      {footer}
    </form>
  );
}

export function Field({
  label,
  type = "text",
  value,
  onChange,
  autoComplete,
}: {
  label: string;
  type?: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
        autoComplete={autoComplete}
        required
      />
    </label>
  );
}
