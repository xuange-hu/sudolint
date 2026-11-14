"""The demo corpora: every rule in the table fires by name."""

from __future__ import annotations

from sudolint import demo
from sudolint.rules import REGISTRY


def test_three_corpora():
    results = demo.reports()
    assert len(results) == 3
    assert [name for name, _ in results] == demo.names()
    assert demo.names() == sorted(demo.names())


def test_every_corpus_has_findings():
    for name, report in demo.reports():
        assert report.count > 0, f"corpus {name} produced no findings"


def test_full_rule_coverage():
    fired, total = demo.coverage()
    assert total == len(REGISTRY)
    missing = {item.id for item in REGISTRY} - fired
    assert not missing, f"rules never fired in the demo: {sorted(missing)}"


def test_coverage_is_stable_between_runs():
    assert demo.coverage()[0] == demo.coverage()[0]


def test_aliases_corpus_exercises_alias_pass():
    by_name = dict(demo.reports())
    report = by_name["alias-traps"]
    assert {"SUD033", "SUD034", "SUD035", "SUD036", "SUD037", "SUD038", "SUD039"} <= report.fired
