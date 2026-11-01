"""Module boundaries from 02_TECHNICAL_ARCHITECTURE.md §4 exist and are documented."""

import importlib

import pytest

from sentinelops.cli.__main__ import main as cli_main

BOUNDARY_MODULES = [
    "identity",
    "platform",
    "tenancy",
    "authz",
    "catalog",
    "secrets",
    "probe_policy",
    "probes",
    "probes.http",
    "scheduler",
    "measurements",
    "incidents",
    "notifications",
    "status_pages",
    "realtime",
    "audit",
]


@pytest.mark.parametrize("name", BOUNDARY_MODULES)
def test_boundary_module_is_importable(name: str) -> None:
    module = importlib.import_module(f"sentinelops.{name}")
    assert module.__doc__


def test_cli_prints_help_without_a_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main([]) == 0
    assert "usage: sentinelops" in capsys.readouterr().out
