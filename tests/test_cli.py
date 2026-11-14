"""The CLI: subcommands, exit codes and the --fail-on gate contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from sudolint.cli import main

CLEAN_FILE = "ops ALL = /usr/bin/systemctl status app\n"
BAD_FILE = "ops ALL = /bin/bash\nroot ALL = (ALL) ALL\n"


def _write(tmp_path: Path, name: str, body: str) -> str:
    target = tmp_path / name
    target.write_text(body, encoding="utf-8")
    return str(target)


def test_scan_clean_file_exits_zero(tmp_path: Path, capsys):
    rc = main(["scan", _write(tmp_path, "clean.sudoers", CLEAN_FILE)])
    assert rc == 0


def test_scan_bad_file_exits_one_at_fail_on_high(tmp_path: Path):
    rc = main(["scan", _write(tmp_path, "bad.sudoers", BAD_FILE), "--quiet"])
    assert rc == 1


def test_scan_bad_file_exits_zero_at_fail_on_critical_only(tmp_path: Path):
    high_only = "ops ALL = /usr/bin/less /var/log/syslog\n"
    rc = main(["scan", _write(tmp_path, "high.sudoers", high_only), "--quiet", "--fail-on", "critical"])
    assert rc == 0


def test_scan_fail_on_none_never_fails(tmp_path: Path):
    rc = main(["scan", _write(tmp_path, "bad.sudoers", BAD_FILE), "--quiet", "--fail-on", "none"])
    assert rc == 0


def test_scan_json_report(tmp_path: Path, capsys):
    rc = main(["scan", _write(tmp_path, "bad.sudoers", BAD_FILE), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    assert '"summary"' in out and '"rule"' in out


def test_scan_sarif_report(tmp_path: Path, capsys):
    main(["scan", _write(tmp_path, "bad.sudoers", BAD_FILE), "--sarif"])
    out = capsys.readouterr().out
    assert '"2.1.0"' in out and "sudolint" in out


def test_scan_directory_finds_sudoers_shaped_files(tmp_path: Path, capsys):
    (tmp_path / "sudoers.d").mkdir()
    (tmp_path / "sudoers.d" / "app").write_text(BAD_FILE, encoding="utf-8")
    (tmp_path / "readme.txt").write_text("not a sudoers file\n", encoding="utf-8")
    rc = main(["scan", str(tmp_path), "--quiet"])
    assert rc == 1


def test_scan_missing_path_exits_two():
    assert main(["scan", "no/such/file.sudoers"]) == 2


def test_scan_directory_with_no_sudoers_exits_two(tmp_path: Path):
    assert main(["scan", str(tmp_path)]) == 2


def test_text_subcommand_auges_inline_text(capsys):
    rc = main(["text", "ops ALL = /bin/bash"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "SUD004" in out


def test_text_subcommand_clean_input(capsys):
    rc = main(["text", CLEAN_FILE])
    assert rc == 0


def test_text_sarif_flag(capsys):
    main(["text", BAD_FILE, "--sarif"])
    assert '"2.1.0"' in capsys.readouterr().out


def test_demo_exits_zero_and_covers_the_table(capsys):
    rc = main(["demo", "--quiet"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "41/41" in out
    assert "NOT fired" not in out


def test_rules_lists_all_41(capsys):
    main(["rules"])
    out = capsys.readouterr().out
    assert "41 rules" in out
    assert "SUD001" in out and "SUD041" in out


def test_rules_json_is_parseable(capsys):
    import json

    main(["rules", "--json"])
    table = json.loads(capsys.readouterr().out)
    assert len(table) == 41
    assert all({"id", "title", "severity", "stage", "why", "fix"} <= set(item) for item in table)


def test_explain_known_rule(capsys):
    rc = main(["explain", "sud004"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Grant on a shell" in out


def test_explain_unknown_rule_exits_two(capsys):
    rc = main(["explain", "SUD999"])
    assert rc == 2


def test_version(capsys):
    from sudolint.cli import build_parser

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0


def test_no_subcommand_exits_two(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
