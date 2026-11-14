"""README contract: the numbers a visitor reads must match the engine."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sudolint.rules import REGISTRY

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("readme", ["README.md", "README_CN.md"], ids=["en", "cn"])
def test_rule_count_in_readme_matches_the_table(readme: str):
    body = (ROOT / readme).read_text(encoding="utf-8")
    count = len(REGISTRY)
    matches = re.findall(r"(\d+)\s*(?:rules|条规则)", body)
    assert matches, f"{readme} never states the rule count"
    assert str(count) in matches, f"{readme} states rule counts {matches} but the table has {count}"


@pytest.mark.parametrize("readme", ["README.md", "README_CN.md"], ids=["en", "cn"])
def test_readme_carries_a_three_step_quickstart(readme: str):
    body = (ROOT / readme).read_text(encoding="utf-8")
    for step in ("pip install", "sudolint demo", "sudolint scan"):
        assert step in body, f"{readme} quickstart is missing `{step}`"


def test_no_host_specific_paths_in_readmes():
    for name in ("README.md", "README_CN.md"):
        body = (ROOT / name).read_text(encoding="utf-8")
        assert "C:\\" not in body
        assert "/Users/" not in body
