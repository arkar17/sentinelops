import type { OrgRole } from "./api.ts";

// UI hints only, mirroring PERMISSION_MATRIX.md. The server enforces every permission.
const MATRIX: Record<string, OrgRole[]> = {
  "ORG.update": ["ORG_OWNER"],
  "ORG.audit.view": ["ORG_OWNER", "ORG_ADMIN"],
  "MEM.invite": ["ORG_OWNER", "ORG_ADMIN"],
  "MEM.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "PRJ.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "MON.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "MON.view_config": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "MON.check_now": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "DOM.view": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "DOM.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "INC.acknowledge": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "INC.assign": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "INC.comment": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "INC.resolve": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "NTF.view": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "NTF.channel.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "NTF.channel.test": ["ORG_OWNER", "ORG_ADMIN"],
  "NTF.route.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "NTF.delivery.view": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
  "STP.manage": ["ORG_OWNER", "ORG_ADMIN"],
  "STP.publish": ["ORG_OWNER", "ORG_ADMIN"],
  "RPT.export": ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER"],
};

export function can(role: OrgRole, action: string): boolean {
  return MATRIX[action]?.includes(role) ?? false;
}

/** Roles this actor may assign or act on (PERMISSION_MATRIX.md §4). */
export function assignableRoles(role: OrgRole): OrgRole[] {
  if (role === "ORG_OWNER") return ["ORG_OWNER", "ORG_ADMIN", "ORG_MEMBER", "VIEWER"];
  if (role === "ORG_ADMIN") return ["ORG_MEMBER", "VIEWER"];
  return [];
}

export const ROLE_LABELS: Record<OrgRole, string> = {
  ORG_OWNER: "Owner",
  ORG_ADMIN: "Admin",
  ORG_MEMBER: "Member",
  VIEWER: "Viewer",
};
