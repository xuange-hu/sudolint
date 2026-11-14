"""Built-in corpora that between them trigger every rule in the table.

One call proves the parser, the three passes and the whole rule table work
end to end, with no files of your own needed. The corpora are intentionally
outrageous: each line exists to trip exactly one rule, so a rule that stops
firing is a regression you can see by name.
"""

from __future__ import annotations

from .engine import run
from .parser import parse
from .rules import REGISTRY

_CORPORA: dict[str, str] = {
    "broad-grants": "\n".join(
        [
            "# the kitchen sink: every grant an auditor dreads, in one file",
            "Defaults !env_reset",
            "Defaults timestamp_timeout=-1",
            "Defaults rootpw",
            "Defaults !secure_path",
            "Defaults !use_pty",
            "Defaults !requiretty",
            'Defaults env_keep += "LD_PRELOAD PYTHONPATH"',
            "root ALL = (ALL) ALL",
            "ALL ALL = /usr/bin/id",
            "deploy ALL = NOPASSWD: ALL",
            "ops ALL = /bin/bash",
            "ops ALL = /usr/bin/su",
            "ops ALL = /usr/bin/vim /etc/hosts",
            "ops ALL = /usr/bin/less /var/log/syslog",
            "ops ALL = /usr/bin/python3 /opt/scripts/report.py",
            "ops ALL = /bin/cp /var/www/html /srv/backup",
            "ops ALL = /usr/bin/chmod 777 /var/www",
            "ops ALL = /bin/mount /dev/sdb1 /mnt/data",
            "ops ALL = /usr/bin/strace -p 1",
            "ops ALL = /usr/bin/find /var -name *",
            "deploy ALL = /usr/bin/apt install *",
            "ops ALL = /usr/bin/whois* --verbose",
            "ops ALL = /usr/bin/tar -czf /var/backups/home.tgz /home/*",
            "ops ALL = rsync -a /var/www /backup",
            "ops ALL = /tmp/cleanup.sh",
            "ops ALL = SETENV: /usr/bin/systemctl restart app",
            "ops ALL = (ALL) /usr/bin/systemctl",
            "ops ALL = (root:ALL) /usr/bin/docker",
            'ops ALL = /usr/bin/logger "deploy done; cleanup"',
            "ops ALL = ALL, !/usr/bin/su",
            "ops ALL = NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx",
        ]
    )
    + "\n",
    "alias-traps": "\n".join(
        [
            "# aliases that lie: dead text, cycles, hidden ALL",
            "#include sudoers.local",
            "User_Alias EVERYONE = ALL",
            "User_Alias pkgops = %deploy",
            "Cmnd_Alias UNUSED_TOOLS = /usr/bin/htop",
            "Cmnd_Alias EVERYTHING = ALL",
            "Cmnd_Alias DUP_NAME = /usr/bin/systemctl status app",
            "Cmnd_Alias DUP_NAME = /usr/bin/systemctl restart app",
            "Cmnd_Alias LOOP_A = LOOP_B",
            "Cmnd_Alias LOOP_B = LOOP_A",
            "Cmnd_Alias PAGER_CMDS = /usr/bin/less /var/log/syslog, /usr/bin/more /var/log/daemon.log",
            "deploy ALL = NOPASSWD: EVERYTHING",
            "deploy ALL = SOMETOOLS",
            "ops ALL = PAGER_CMDS",
            "%dev ALL = EVERYONE",
        ]
    )
    + "\n",
    "last-match-wins": "\n".join(
        [
            "# the later spec silently replaces the earlier one",
            "%ops ALL = /usr/bin/systemctl status app",
            "%ops ALL = /usr/bin/systemctl restart app",
            "Cmnd_Alias BROKEN = /usr/bin/htop",
            "Cmnd_Alias BROKEN = /usr/bin/top",
            "include sudoers.local.d",
            "this line has no equals sign and no keyword",
        ]
    )
    + "\n",
}


def names() -> list[str]:
    return sorted(_CORPORA)


def reports() -> list[tuple[str, object]]:
    """(name, Report) for every corpus, in name order."""
    out = []
    for name in names():
        app = parse(_CORPORA[name], source=name)
        out.append((name, run(app, target=name)))
    return out


def coverage() -> tuple[set[str], int]:
    """Rule ids fired across all corpora, and the size of the table."""
    fired: set[str] = set()
    for _name, report in reports():
        fired |= report.fired
    return fired, len(REGISTRY)


__all__ = ["coverage", "names", "reports"]
