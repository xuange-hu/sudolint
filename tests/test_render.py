"""Text, JSON and SARIF rendering: the offsets survive every format."""

from __future__ import annotations

import json

from helpers import report_from


def _bad_report():
    return report_from("ops ALL = /bin/bash\n", source="sudoers")


def test_text_names_rule_severity_line_and_offset():
    from sudolint.render import text

    body = text(_bad_report())
    assert "SUD004" in body
    assert "[critical]" in body
    assert "line 1" in body
    assert "offset 0x" in body
    assert "saw:" in body
    assert "fix:" in body


def test_text_clean_file_says_no_findings():
    from sudolint.render import text

    body = text(report_from("ops ALL = /usr/bin/id\n"))
    assert "no findings" in body


def test_json_summary_shape():
    from sudolint.render import json_dict

    payload = json_dict(_bad_report())
    assert payload["source"] == "sudoers"
    summary = payload["summary"]
    assert summary["findings"] >= 1
    assert summary["risk"] >= 6
    assert "critical" in summary["by_severity"]
    finding = payload["findings"][0]
    for key in ("rule", "severity", "message", "line", "offset", "length", "saw", "fix"):
        assert key in finding


def test_to_json_round_trips():
    from sudolint.render import to_json

    payload = json.loads(to_json(_bad_report()))
    assert payload["summary"]["findings"] == _bad_report().count


def test_sarif_carries_byte_offsets_and_forward_slash_uris():
    from sudolint.render import to_sarif

    sarif = json.loads(to_sarif(_bad_report()))
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sudolint"
    assert run["tool"]["driver"]["version"]
    result = run["results"][0]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    assert region["byteOffset"] >= 0
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_rules_are_sorted_and_deduplicated():
    from sudolint.render import to_sarif

    report = report_from("ops ALL = /bin/bash\nroot ALL = (ALL) ALL\n")
    sarif = json.loads(to_sarif(report))
    ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert ids == sorted(set(ids))


def test_brief_is_one_line():
    from sudolint.render import brief

    line = brief(_bad_report())
    assert line.count("\n") == 0
    assert "sudoers" in line and "risk=" in line
