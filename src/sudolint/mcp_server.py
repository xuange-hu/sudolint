"""MCP facade: six tools over the same engine the CLI runs.

Every tool is a thin wrapper over a function that already exists in this
package, so what an agent sees and what a human runs cannot drift apart. The
imports of the optional ``mcp`` extra stay inside this module so the core
package keeps its zero-dependency promise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import demo, render
from .engine import run
from .parser import looks_like_sudoers, parse, parse_file
from .rules import REGISTRY

_SEVERITIES = ("note", "low", "medium", "high", "critical")


def _fail_threshold(name: str) -> int:
    return _SEVERITIES.index(name) if name in _SEVERITIES else -1


def _failed(report, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _fail_threshold(fail_on)
    return any(_fail_threshold(f.severity) >= threshold for f in report.findings)


def sudolint_scan(path: str, fail_on: str = "high") -> str:
    """Audit a sudoers file or a directory of them.

    Returns the text report with one block per file: severity, rule id, line,
    byte offset and the exact bytes that caused it. Set fail_on to none, note,
    low, medium, high or critical to decide what a nonzero exit would mean.
    """
    target = Path(path)
    if not target.exists():
        return f"sudolint: no such file or directory: {path}"

    files: list[Path]
    if target.is_file():
        files = [target]
    else:
        files = []
        for candidate in sorted(target.rglob("*")):
            if not candidate.is_file():
                continue
            if candidate.name == "sudoers" or "sudoers.d" in candidate.parts:
                files.append(candidate)
                continue
            try:
                body = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if looks_like_sudoers(body):
                files.append(candidate)
    if not files:
        return f"sudolint: no sudoers files under {path}"

    blocks = []
    failing = False
    for file_path in files:
        report = run(parse_file(file_path), target=str(file_path))
        blocks.append(render.text(report, color=False))
        if _failed(report, fail_on):
            failing = True
    header = f"{'FAIL' if failing else 'PASS'} at fail_on={fail_on}\n\n"
    return header + "\n".join(blocks)


def sudolint_text(text: str, source: str = "<text>", fail_on: str = "high") -> str:
    """Audit sudoers text passed in directly, without touching the filesystem.

    Useful when the config comes from a conversation, a pull request or an
    Ansible template. The same rules run as on a file.
    """
    app = parse(text, source=source)
    report = run(app, target=source)
    verdict = "FAIL" if _failed(report, fail_on) else "PASS"
    return f"{verdict} at fail_on={fail_on}\n\n" + render.text(report, color=False)


def sudolint_rules(stage: int | None = None, severity: str | None = None) -> str:
    """List the rule table, filterable by stage (1 line, 2 alias, 3 file) or
    by severity, as id, severity, stage and title."""
    rows = []
    for item in sorted(REGISTRY, key=lambda rule: rule.id):
        if stage is not None and item.stage != stage:
            continue
        if severity is not None and item.severity != severity:
            continue
        rows.append(f"{item.id}  {item.severity:<8s} stage {item.stage}  {item.title}")
    if not rows:
        return "sudolint: no rules match that filter"
    return "\n".join(rows) + f"\n\n{len(rows)} rules"


def sudolint_explain(rule: str) -> str:
    """Explain one rule: what it detects, why it matters, and the fix."""
    wanted = rule.strip().upper()
    for item in REGISTRY:
        if item.id == wanted:
            return (
                f"{item.id}  {item.title}\n"
                f"severity: {item.severity} (score {item.score})   stage: {item.stage}\n\n"
                f"why it matters\n{item.why}\n\n"
                f"fix\n{item.fix}"
            )
    known = ", ".join(item.id for item in sorted(REGISTRY, key=lambda rule: rule.id))
    return f"sudolint: no rule {wanted}. Known ids: {known}"


def sudolint_sarif(path: str) -> str:
    """Audit a sudoers file and return SARIF 2.1.0, ready for a GitHub
    code-scanning upload."""
    target = Path(path)
    if not target.is_file():
        return f"sudolint: not a file: {path}"
    report = run(parse_file(target), target=str(target))
    return render.to_sarif(report)


def sudolint_demo() -> str:
    """Audit three built-in sudoers files that between them trigger every rule.

    One call proves the parser, the three passes and the whole table work end
    to end, with no files of your own needed.
    """
    results = demo.reports()
    fired, total = demo.coverage()
    lines = [render.brief(report) for _, report in results]
    lines.append("")
    lines.append(f"rules fired: {len(fired)}/{total}")
    missing = sorted(item.id for item in REGISTRY if item.id not in fired)
    if missing:
        lines.append("NOT fired: " + " ".join(missing))
    else:
        lines.append("every rule in the table has a sample line that triggers it")
    return "\n".join(lines)


def tool_manifest() -> list[dict[str, str]]:
    """Names and descriptions, for a CLI self-check and for tests."""
    tools = [
        sudolint_scan,
        sudolint_text,
        sudolint_rules,
        sudolint_explain,
        sudolint_sarif,
        sudolint_demo,
    ]
    return [{"name": tool.__name__, "description": tool.__doc__ or ""} for tool in tools]


def build_server() -> Any:
    """Build the MCP server, importing the optional extra lazily."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("sudolint")
    server.tool()(sudolint_scan)
    server.tool()(sudolint_text)
    server.tool()(sudolint_rules)
    server.tool()(sudolint_explain)
    server.tool()(sudolint_sarif)
    server.tool()(sudolint_demo)
    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
