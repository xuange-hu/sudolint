"""Entry points: `python -m sudolint`, the package surface and the MCP manifest."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import sudolint
from sudolint.mcp_server import tool_manifest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sudolint", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        cwd=str(ROOT),
        env={"PYTHONPATH": str(SRC), "PATH": "", "SYSTEMROOT": "C:\\Windows"},
    )


def test_package_exports():
    assert sudolint.__all__ == ["Report", "__version__", "parse", "parse_file", "run"]
    assert callable(sudolint.parse)
    assert callable(sudolint.parse_file)
    assert callable(sudolint.run)
    assert sudolint.__version__ == "0.1.0"


def test_module_runs_version():
    proc = _run("--version")
    assert proc.returncode == 0, proc.stderr
    assert "sudolint 0.1.0" in proc.stdout


def test_module_runs_rules():
    proc = _run("rules")
    assert proc.returncode == 0, proc.stderr
    assert "41 rules" in proc.stdout


def test_module_runs_demo():
    proc = _run("demo", "--no-color")
    assert proc.returncode == 0, proc.stderr
    assert "rules fired: 41/41" in proc.stdout


def test_module_requires_a_subcommand():
    proc = _run()
    assert proc.returncode == 2
    assert "usage" in (proc.stderr + proc.stdout).lower()


def test_parse_and_run_from_the_package_api():
    report = sudolint.run(
        sudolint.parse("ops ALL = /bin/bash\n", source="api"),
        target="api",
    )
    assert {"SUD004"} <= report.fired


MANIFEST = tool_manifest()


def test_manifest_has_six_tools():
    assert len(MANIFEST) == 6
    names = {entry["name"] for entry in MANIFEST}
    assert names == {
        "sudolint_scan",
        "sudolint_text",
        "sudolint_rules",
        "sudolint_explain",
        "sudolint_sarif",
        "sudolint_demo",
    }


@pytest.mark.parametrize("entry", MANIFEST, ids=lambda entry: entry["name"])
def test_every_tool_has_a_description(entry):
    assert len(entry["description"]) >= 20, f"{entry['name']} has no real description"


def test_console_scripts_resolve(tmp_path: Path):
    """The pyproject entry points name callables that exist in the package."""
    import importlib

    targets = {
        "sudolint": "sudolint.cli:main",
        "sudolint-mcp": "sudolint.mcp_server:main",
    }
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for name, target in targets.items():
        assert f'{name} = "{target}"' in pyproject
        module_name, attr = target.split(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attr))


def test_version_is_consistent_with_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = next(line for line in pyproject.splitlines() if line.startswith("version = "))
    assert f'"{sudolint.__version__}"' in match
