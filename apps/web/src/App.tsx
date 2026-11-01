import { useEffect } from "react";
import { apiRequest, type MyOrganizations } from "./api.ts";
import { AuthProvider } from "./auth.tsx";
import { useAuth } from "./auth-context.ts";
import { Link } from "./components.tsx";
import { useLoad } from "./hooks.ts";
import { AdminOrganizationPage, AdminOrganizationsPage } from "./pages/AdminOrgPages.tsx";
import { AdminDomainExceptionsPage } from "./pages/DomainPages.tsx";
import {
  AdminAdminsPage,
  AdminAuditPage,
  AdminDashboardPage,
  AdminSettingsPage,
} from "./pages/AdminPages.tsx";
import {
  AcceptAdminInvitePage,
  AcceptInvitePage,
  ActivatePage,
  ForgotPasswordPage,
  LoginPage,
  ResetPasswordPage,
} from "./pages/AuthPages.tsx";
import { AdminSecurityPage, MfaEnrollPage, MfaVerifyPage } from "./pages/MfaPages.tsx";
import { OrgPicker, OrgShell } from "./pages/OrgPages.tsx";
import { PublicStatusPage } from "./pages/StatusPages.tsx";
import { navigate, ORG_SECTIONS, type OrgSection, usePath } from "./router.ts";

const PUBLIC_PAGES: Record<string, () => React.JSX.Element> = {
  "/login": LoginPage,
  "/activate": ActivatePage,
  "/forgot-password": ForgotPasswordPage,
  "/reset-password": ResetPasswordPage,
  "/accept-admin-invite": AcceptAdminInvitePage,
  "/accept-invite": AcceptInvitePage,
};

const ADMIN_PAGES: Record<string, () => React.JSX.Element> = {
  "/admin": AdminDashboardPage,
  "/admin/admins": AdminAdminsPage,
  "/admin/organizations": AdminOrganizationsPage,
  "/admin/domain-exceptions": AdminDomainExceptionsPage,
  "/admin/settings": AdminSettingsPage,
  "/admin/audit": AdminAuditPage,
  "/admin/security": AdminSecurityPage,
};

function Redirect({ to }: { to: string }) {
  useEffect(() => {
    navigate(to);
  }, [to]);
  return null;
}

function OrgSwitcher({ path }: { path: string }) {
  const { data } = useLoad<MyOrganizations>("/api/me/organizations");
  if (!data || data.organizations.length === 0) return null;
  const currentSlug = /^\/o\/([^/]+)/.exec(path)?.[1] ?? "";
  return (
    <label>
      <span className="visually-hidden">Organization</span>
      <select
        aria-label="Organization"
        value={currentSlug}
        onChange={(event) => {
          const target = data.organizations.find((o) => o.slug === event.target.value);
          if (!target) return;
          void apiRequest("PUT", "/api/me/preferences", {
            selected_org_id: target.organization_id,
          }).finally(() => {
            navigate(`/o/${target.slug}`);
          });
        }}
      >
        <option value="" disabled>
          Choose organization…
        </option>
        {data.organizations.map((o) => (
          <option key={o.organization_id} value={o.slug}>
            {o.name}
          </option>
        ))}
      </select>
    </label>
  );
}

function Header() {
  const { me, logout } = useAuth();
  const path = usePath();
  return (
    <header className="topbar">
      <strong>SentinelOps</strong>
      {me && (
        <nav>
          {me.is_platform_admin && !me.mfa_pending && (
            <>
              <Link to="/admin">Dashboard</Link>
              <Link to="/admin/organizations">Organizations</Link>
              <Link to="/admin/domain-exceptions">Domain exceptions</Link>
              <Link to="/admin/admins">Administrators</Link>
              <Link to="/admin/settings">Settings</Link>
              <Link to="/admin/audit">Audit</Link>
              <Link to="/admin/security">Security</Link>
            </>
          )}
          {!me.mfa_pending && <OrgSwitcher key={me.id} path={path} />}
          <span className="muted">{me.email}</span>
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
        </nav>
      )}
    </header>
  );
}

function OrgRoutes({ path }: { path: string }) {
  const { data, error } = useLoad<MyOrganizations>("/api/me/organizations");
  if (error) return <p role="alert" className="error">{error}</p>;
  if (!data) return <p role="status">Loading…</p>;
  const match = /^\/o\/([^/]+)(?:\/([^/]+))?((?:\/[^/]+){0,2})\/?$/.exec(path);
  if (!match) {
    const selected = data.organizations.find((o) => o.organization_id === data.selected_org_id);
    const only = data.organizations.length === 1 ? data.organizations[0] : undefined;
    const target = selected ?? only;
    return target ? <Redirect to={`/o/${target.slug}`} /> : <OrgPicker memberships={data.organizations} />;
  }
  const membership = data.organizations.find((o) => o.slug === match[1]);
  const section = (match[2] ?? "") as OrgSection;
  if (!membership || !ORG_SECTIONS.includes(section)) {
    return (
      <p role="alert" className="error">
        Organization not found.
      </p>
    );
  }
  const rest = (match[3] ?? "").split("/").filter(Boolean);
  return (
    <OrgShell
      key={membership.organization_id}
      membership={membership}
      section={section}
      rest={rest}
    />
  );
}

function Routes() {
  const path = usePath();
  const { me, loading } = useAuth();

  const Public = PUBLIC_PAGES[path];
  if (Public) {
    return <Public />;
  }
  const publicStatus = /^\/status\/([a-z0-9-]{3,40})$/.exec(path);
  if (publicStatus?.[1]) {
    return <PublicStatusPage slug={publicStatus[1]} />;
  }
  if (loading) {
    return <p role="status">Loading…</p>;
  }
  if (!me) {
    return <Redirect to="/login" />;
  }
  if (me.mfa_pending === "VERIFY") return <MfaVerifyPage />;
  if (me.mfa_pending === "ENROLL") return <MfaEnrollPage />;
  const adminOrg = /^\/admin\/organizations\/([0-9a-f-]{36})$/.exec(path);
  const Admin = ADMIN_PAGES[path];
  if (Admin || adminOrg) {
    if (!me.is_platform_admin) {
      return (
        <p role="alert" className="error">
          Platform administrator access is required for this page.
        </p>
      );
    }
    return adminOrg?.[1] ? <AdminOrganizationPage id={adminOrg[1]} /> : Admin ? <Admin /> : null;
  }
  if (path === "/" && me.is_platform_admin) {
    return <Redirect to="/admin" />;
  }
  return <OrgRoutes path={path} />;
}

export function App() {
  return (
    <AuthProvider>
      <Header />
      <main className="shell">
        <Routes />
      </main>
    </AuthProvider>
  );
}
