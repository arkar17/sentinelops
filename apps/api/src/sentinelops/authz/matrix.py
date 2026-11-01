"""Organization-plane permission table, transcribed from PERMISSION_MATRIX.md §3.

Cells marked ◐ (allowed with a restriction) are listed as allowed here; the restriction is enforced
by the owning service (e.g. tenancy.rules). tests/test_authz_matrix.py parses the Markdown matrix
and fails if this table drifts from it. Unlisted actions are denied (default deny).
"""

from sentinelops.tenancy.models import OrgRole

_O, _A, _M, _V = OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER, OrgRole.VIEWER
_ALL = frozenset({_O, _A, _M, _V})
_OAM = frozenset({_O, _A, _M})
_OA = frozenset({_O, _A})
_O_ONLY = frozenset({_O})
_NONE: frozenset[str] = frozenset()

ORG_PERMISSIONS: dict[str, frozenset[str]] = {
    "ORG.view": _ALL,
    "ORG.update": _O_ONLY,
    "ORG.audit.view": _OA,
    "ORG.state.change": _NONE,
    "ORG.delete": _NONE,
    "MEM.list": _ALL,
    "MEM.invite": _OA,
    "MEM.invitation.revoke": _OA,
    "MEM.role.change": _OA,
    "MEM.status.change": _OA,
    "MEM.remove": _OA,
    "MEM.leave": _ALL,
    "PRJ.view": _ALL,
    "PRJ.create": _OA,
    "PRJ.update": _OA,
    "PRJ.archive": _OA,
    "DOM.view": _OAM,
    "DOM.manage": _OA,
    "MON.view": _ALL,
    "MON.view_config": _OAM,
    "MON.create": _OA,
    "MON.update": _OA,
    "MON.secret.write": _OA,
    "MON.secret.read": _NONE,
    "MON.pause": _OA,
    "MON.resume": _OA,
    "MON.archive": _OA,
    "MON.check_now": _OAM,
    "INC.view": _ALL,
    "INC.acknowledge": _OAM,
    "INC.assign": _OAM,
    "INC.comment": _OAM,
    "INC.resolve": _OAM,
    "NTF.view": _OAM,
    "NTF.channel.manage": _OA,
    "NTF.channel.test": _OA,
    "NTF.route.manage": _OA,
    "NTF.delivery.view": _OAM,
    "RPT.dashboard": _ALL,
    "RPT.view": _ALL,
    "RPT.export": _OAM,
    "STP.view": _ALL,
    "STP.manage": _OA,
    "STP.publish": _OA,
    "SELF.list_orgs": _ALL,
    "SELF.switch_org": _ALL,
    "SELF.profile": _ALL,
}


def allows(role: str, action: str) -> bool:
    return role in ORG_PERMISSIONS.get(action, _NONE)
