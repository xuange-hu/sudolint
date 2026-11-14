"""Shared construction helpers.

Every test builds its input from text, so nothing in the repository depends on
a file that exists only on one machine.
"""

from __future__ import annotations

from sudolint import parse, run
from sudolint.model import App, Finding, Report

CLEAN = "ops ALL = /usr/bin/systemctl status app\n"


def app_from(text: str, source: str = "sudoers") -> App:
    return parse(text, source=source)


def report_from(text: str, source: str = "sudoers") -> Report:
    return run(app_from(text, source), target=source)


def findings_for(report: Report, rule_id: str) -> list[Finding]:
    return [finding for finding in report.findings if finding.rule == rule_id]


def fired_rules(report: Report) -> set[str]:
    return {finding.rule for finding in report.findings}
