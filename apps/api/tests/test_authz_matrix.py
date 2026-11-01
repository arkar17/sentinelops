"""PERMISSION_MATRIX.md is normative: the code's tables must match it cell for cell (AC-025)."""

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from sentinelops.api.app import create_app
from sentinelops.authz.matrix import ORG_PERMISSIONS, allows
from sentinelops.config import Settings
from sentinelops.platform.dependencies import PLATFORM_ACTIONS, PlatformPermission
from sentinelops.tenancy.context import OrgPermission
from sentinelops.tenancy.models import OrgRole

MATRIX = Path(__file__).resolve().parents[3] / "docs" / "baseline-v1.0" / "PERMISSION_MATRIX.md"
ROLES = (OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER, OrgRole.VIEWER)


def _section(title: str) -> str:
    text = MATRIX.read_text()
    start = text.index(title)
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else None]


def _rows(section: str, columns: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == columns and re.match(r"^[A-Z]+\.", cells[0]):
            rows.append(cells)
    return rows


def _actions(cell: str) -> list[str]:
    return [a.strip() for a in cell.split("/")]


def _allowed(cell: str) -> bool:
    return cell.startswith(("✅", "◐"))


def org_matrix() -> dict[str, dict[str, bool]]:
    parsed: dict[str, dict[str, bool]] = {}
    for cells in _rows(_section("## 3. Organization plane"), 6):
        if cells[0].startswith("PUB."):
            continue
        for action in _actions(cells[0]):
            parsed[action] = {
                role: _allowed(cell) for role, cell in zip(ROLES, cells[2:], strict=True)
            }
    return parsed


def test_matrix_document_is_found_and_parsed() -> None:
    parsed = org_matrix()
    assert len(parsed) >= 40
    assert parsed["MON.create"] == {
        OrgRole.OWNER: True,
        OrgRole.ADMIN: True,
        OrgRole.MEMBER: False,  # OD-04: ORG_MEMBER cannot edit monitors
        OrgRole.VIEWER: False,
    }


def test_code_matches_every_organization_cell() -> None:
    parsed = org_matrix()
    assert set(parsed) == set(ORG_PERMISSIONS)
    mismatches = [
        (action, role)
        for action, cells in parsed.items()
        for role, expected in cells.items()
        if allows(role, action) != expected
    ]
    assert mismatches == []


def test_platform_actions_match_document() -> None:
    allowed = set[str]()
    for cells in _rows(_section("## 2. Platform plane"), 4):
        if _allowed(cells[2]):
            allowed.update(_actions(cells[0]))
    assert allowed == set(PLATFORM_ACTIONS)


def test_unknown_actions_are_denied() -> None:
    assert not allows(OrgRole.OWNER, "ORG.does_not_exist")
    with pytest.raises(ValueError, match="not a permitted"):
        PlatformPermission("PLT.impersonate")


def _declared(dependant: Dependant) -> list[object]:
    found: list[object] = []
    for dep in dependant.dependencies:
        if isinstance(dep.call, OrgPermission | PlatformPermission):
            found.append(dep.call)
        found.extend(_declared(dep))
    return found


def _api_routes(routes: list[Any]) -> list[APIRoute]:
    """Flatten routes; this FastAPI version nests included routers (``original_router``)."""
    flat: list[APIRoute] = []
    for route in routes:
        if isinstance(route, APIRoute):
            flat.append(route)
        elif (nested := getattr(route, "original_router", None)) is not None:
            flat.extend(_api_routes(list(nested.routes)))
    return flat


def test_every_plane_route_declares_exactly_one_action(settings: Settings) -> None:
    app = create_app(settings)
    checked = 0
    for route in _api_routes(list(app.routes)):
        declared = _declared(route.dependant)
        if route.path.startswith("/api/orgs/"):
            assert [type(d) for d in declared] == [OrgPermission], route.path
            assert declared[0].action in ORG_PERMISSIONS  # type: ignore[attr-defined]
            checked += 1
        elif route.path.startswith("/api/admin/"):
            assert [type(d) for d in declared] == [PlatformPermission], route.path
            checked += 1
        else:
            assert declared == [], f"{route.path} is outside the org/platform planes"
    assert checked >= 25
