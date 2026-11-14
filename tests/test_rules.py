"""Every rule fires on a dedicated snippet, and stays quiet on its negatives.

The parametrization is the contract: one snippet per rule id, plus a set of
files that must produce zero findings (or none from a specific rule) so a
loosened matcher cannot sneak back in.
"""

from __future__ import annotations

import pytest
from helpers import findings_for, fired_rules, report_from

from sudolint.rules import REGISTRY, _basename

SNIPPETS = {
    "SUD001": "this line has no equals sign\n",
    "SUD002": "ops ALL = NOPASSWD: ALL\n",
    "SUD003": "root ALL = ALL\n",
    "SUD004": "ops ALL = /bin/bash\n",
    "SUD005": "ops ALL = /usr/bin/su\n",
    "SUD006": "ops ALL = /usr/bin/vim /etc/hosts\n",
    "SUD007": "ops ALL = /usr/bin/less /var/log/syslog\n",
    "SUD008": "ops ALL = /usr/bin/python3 /opt/scripts/report.py\n",
    "SUD009": "ops ALL = /bin/cp /var/www/html /srv/backup\n",
    "SUD010": "ops ALL = /usr/bin/chmod 777 /var/www\n",
    "SUD011": "ops ALL = /bin/mount /dev/sdb1 /mnt/data\n",
    "SUD012": "ops ALL = /usr/bin/strace -p 1\n",
    "SUD013": "ops ALL = /usr/bin/find /var -name *\n",
    "SUD014": "ops ALL = /usr/bin/apt install htop\n",
    "SUD015": "ops ALL = /usr/bin/whois* --verbose\n",
    "SUD016": "ops ALL = /usr/bin/tar -czf /var/backups/home.tgz /home/*\n",
    "SUD017": "ops ALL = rsync -a /var/www /backup\n",
    "SUD018": "ops ALL = /tmp/cleanup.sh\n",
    "SUD019": "ops ALL = SETENV: /usr/bin/systemctl restart app\n",
    "SUD020": "ops ALL = (ALL) /usr/bin/systemctl\n",
    "SUD021": "ops ALL = (root:ALL) /usr/bin/docker\n",
    "SUD022": "ALL ALL = /usr/bin/id\n",
    "SUD023": 'ops ALL = /usr/bin/logger "deploy done; cleanup"\n',
    "SUD024": "ops ALL = ALL, !/usr/bin/su\n",
    "SUD025": ("ops ALL = NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx\n"),
    "SUD026": "Defaults !env_reset\n",
    "SUD027": "Defaults timestamp_timeout=-1\n",
    "SUD028": "Defaults rootpw\n",
    "SUD029": "Defaults !secure_path\n",
    "SUD030": "Defaults !use_pty\n",
    "SUD031": "Defaults !requiretty\n",
    "SUD032": 'Defaults env_keep += "LD_PRELOAD PYTHONPATH"\n',
    "SUD033": "Cmnd_Alias pkgops = /usr/bin/apt\n",
    "SUD034": "ops ALL = SOMETOOLS\n",
    "SUD035": "Cmnd_Alias UNUSED_TOOLS = /usr/bin/htop\n",
    "SUD036": "Cmnd_Alias DUP_NAME = /usr/bin/htop\nCmnd_Alias DUP_NAME = /usr/bin/top\n",
    "SUD037": "Cmnd_Alias LOOP_A = LOOP_B\nCmnd_Alias LOOP_B = LOOP_A\n",
    "SUD038": "User_Alias EVERYONE = ALL\n",
    "SUD039": "Cmnd_Alias EVERYTHING = ALL\n",
    "SUD040": ("%ops ALL = /usr/bin/systemctl status app\n%ops ALL = /usr/bin/systemctl restart app\n"),
    "SUD041": "#include sudoers.local\n",
}


@pytest.mark.parametrize("rule_id", sorted(SNIPPETS))
def test_rule_fires_on_its_snippet(rule_id: str):
    report = report_from(SNIPPETS[rule_id])
    assert rule_id in fired_rules(report), f"{rule_id} did not fire on its snippet: fired={sorted(fired_rules(report))}"


def test_every_registry_id_has_a_snippet():
    ids = {item.id for item in REGISTRY}
    assert ids == set(SNIPPETS), f"missing snippets: {ids - set(SNIPPETS)}"


def test_clean_file_produces_zero_findings():
    report = report_from("ops ALL = /usr/bin/systemctl status app\n")
    assert report.count == 0, "\n".join(f"{f.rule}: {f.message}" for f in report.findings)


def test_comment_only_file_produces_zero_findings():
    report = report_from("# nothing here\n\n")
    assert report.count == 0


def test_sud004_fires_through_a_cmnd_alias():
    report = report_from("Cmnd_Alias SHELL_CMDS = /bin/bash, /bin/zsh\nops ALL = SHELL_CMDS\n")
    hits = findings_for(report, "SUD004")
    assert len(hits) == 2  # one per alias member
    assert all("Cmnd_Alias SHELL_CMDS" in hit.where for hit in hits)


def test_sud002_fires_when_an_alias_member_is_all():
    report = report_from("Cmnd_Alias EVERYTHING = ALL\nops ALL = NOPASSWD: EVERYTHING\n")
    assert findings_for(report, "SUD002")
    assert findings_for(report, "SUD039")


def test_sud002_does_not_fire_without_nopasswd():
    report = report_from("ops ALL = ALL\n")
    assert not findings_for(report, "SUD002")


def test_sud025_respects_an_explicit_passwd_reset():
    report = report_from("ops ALL = NOPASSWD: /usr/bin/a, PASSWD: /usr/bin/systemctl status app\n")
    assert not findings_for(report, "SUD025")


def test_sud013_stays_quiet_on_pinned_find_args():
    report = report_from("ops ALL = /usr/bin/find /var/log -print\n")
    assert not findings_for(report, "SUD013")


def test_sud016_stays_quiet_on_non_escape_commands():
    report = report_from("ops ALL = /usr/bin/systemctl restart app-*\n")
    assert not findings_for(report, "SUD016")


def test_sud032_stays_quiet_on_benign_env_keep():
    report = report_from('Defaults env_keep += "COLORS LANG"\n')
    assert not findings_for(report, "SUD032")


def test_sud027_stays_quiet_on_positive_timeout():
    report = report_from("Defaults timestamp_timeout=15\n")
    assert not findings_for(report, "SUD027")


def test_sud034_and_sud035_cancel_out_when_used():
    report = report_from("Cmnd_Alias TOOLS = /usr/bin/htop\nops ALL = TOOLS\n")
    assert not findings_for(report, "SUD034")
    assert not findings_for(report, "SUD035")


def test_sud040_names_the_first_spec_line():
    report = report_from("%ops ALL = /usr/bin/systemctl status app\n%ops ALL = /usr/bin/systemctl restart app\n")
    hits = findings_for(report, "SUD040")
    assert len(hits) == 1
    assert "line 1" in hits[0].message


def test_sud040_treats_all_hosts_as_matching():
    report = report_from("ops ALL = /usr/bin/systemctl status app\nops web1 = /usr/bin/systemctl restart app\n")
    assert findings_for(report, "SUD040")


def test_alias_cycle_reports_each_member_once():
    report = report_from("Cmnd_Alias LOOP_A = LOOP_B\nCmnd_Alias LOOP_B = LOOP_A\nops ALL = LOOP_A\n")
    hits = findings_for(report, "SUD037")
    assert {hit.line for hit in hits} == {1, 2}


def test_findings_are_sorted_by_severity_then_line():
    report = report_from("ops ALL = /bin/bash\ndefaults_garbage\nDefaults !use_pty\n")
    keys = [f.sort_key() for f in report.findings]
    assert keys == sorted(keys)


def test_risk_saturates_at_100():
    text = "".join(f"user{i} ALL = NOPASSWD: ALL\n" for i in range(9))
    report = report_from(text)
    assert report.risk == 100


def test_basename_handles_backslashes():
    assert _basename("C:\\Windows\\System32\\bash.exe") == "bash.exe"
