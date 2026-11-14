"""The rule table, in three passes.

* Pass 1 reads one line at a time: the command classes in a user spec, the
  tags, the runas form, the Defaults parameters.
* Pass 2 reads aliases: names that never resolve, definitions nobody uses,
  circular Cmnd_Aliases, ALL hidden inside an alias.
* Pass 3 reads the file as a whole: two specs for the same user on the same
  host, where sudoers takes the last one and silently drops the earlier one.

Dangerous-command classification deliberately checks both the command as
written and every Cmnd_Alias it expands to: a file can look clean and grant
NOPASSWD on an alias whose member is a pager. Every rule yields an Issue with
the line and byte offset it is talking about; a rule that cannot name its own
evidence does not ship.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from dataclasses import field as dc_field

from .model import App, CommandItem, UserSpec

# GTFOBins-style classes: commands that grant a shell or write access when run
# as root, independent of arguments.
SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox"}
SU_SUDO = {"su", "sudo"}
EDITORS = {"vi", "vim", "view", "vimdiff", "ex", "nvim", "emacs", "emacsclient", "elvis", "nvi", "rvim"}
PAGERS = {"less", "more", "most"}
INTERP_EXACT = {"perl", "ruby", "tclsh", "wish", "awk", "gawk", "mawk", "sed", "ed", "jshell", "ghci", "irb"}
INTERP_PREFIX = ("python", "php", "node", "lua")
FILEWRITE = {"cp", "mv", "tee", "dd", "install", "ln", "truncate", "mkfifo", "mknod"}
PERMCHANGE = {"chmod", "chown", "chgrp", "chattr", "setfacl", "setcap"}
MOUNTS = {"mount", "umount", "fusermount", "fusermount3"}
DEBUG = {"gdb", "strace", "ltrace"}
PKGMGR = {"apt", "apt-get", "yum", "dnf", "rpm", "dpkg", "pip", "pip3", "gem", "npm", "npx"}
# Commands where a wildcard argument lets the user inject arbitrary ones
# (sudoers docs: a '*' argument spec matches anything, including new options).
WILD_ESCAPE = {
    "tar",
    "rsync",
    "scp",
    "chmod",
    "find",
    "awk",
    "gawk",
    "sed",
    "git",
    "zip",
    "unzip",
    "cpio",
    "pax",
    "xargs",
    "less",
    "more",
    "man",
    "cp",
    "mv",
    "dd",
    "curl",
    "wget",
    "gzip",
    "bzip2",
    "xxd",
}
TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
TMP_EXACT = {"/tmp", "/var/tmp", "/dev/shm"}
METACHARS = (";", "`", "$(", "${", "|", ">", "<", "&&")
DANGEROUS_ENV = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5OPT",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "GIT_ASKPASS",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    score: int
    stage: int  # 1 line, 2 alias, 3 file
    why: str
    fix: str
    check: Callable[[Context], Iterator[Issue]]


@dataclass
class Issue:
    """One rule's complaint, with the bytes that caused it."""

    message: str
    line: int
    offset: int
    length: int = 0
    saw: str = ""
    fix: str = ""
    where: str = ""


@dataclass
class Context:
    """Everything a rule may look at."""

    app: App
    _expansions: dict[str, list[tuple[str, str, int]]] = dc_field(default_factory=dict)

    def specs(self) -> list[UserSpec]:
        return self.app.specs

    def expansion(self, name: str) -> list[tuple[str, str, int]]:
        """Flatten a Cmnd_Alias to (command, args, origin_line), cycles cut.

        Cached per scan: the same alias referenced from ten specs must expand
        to the same list ten times, or two runs over one file could disagree.
        """
        if name in self._expansions:
            return self._expansions[name]
        self._expansions[name] = []  # sentinel breaks cycles
        out: list[tuple[str, str, int]] = []
        from .parser import parse_item

        alias = self.app.aliases.get("Cmnd_Alias", {}).get(name)
        if alias is not None:
            for member in alias.members:
                item = parse_item(member)
                if item.is_alias:
                    sub = self.app.aliases.get("Cmnd_Alias", {}).get(item.alias_name)
                    if sub is not None and sub.name != name:
                        out.extend((cmd, args, sub.lineno) for cmd, args, _line in self.expansion(item.alias_name))
                else:
                    out.append((item.command, item.args, alias.lineno))
        self._expansions[name] = out
        return out

    def resolved(self, item: CommandItem) -> list[tuple[str, str, int]]:
        """What this command entry actually grants: itself, or its alias body."""
        if item.is_alias:
            return self.expansion(item.alias_name)
        return [(item.command, item.args, item.lineno)]


REGISTRY: list[Rule] = []


def rule(rule_id: str, title: str, severity: str, score: int, stage: int, why: str, fix: str) -> Callable:
    def decorate(fn: Callable) -> Callable:
        REGISTRY.append(
            Rule(id=rule_id, title=title, severity=severity, score=score, stage=stage, why=why, fix=fix, check=fn)
        )
        return fn

    return decorate


def _executable() -> list[Rule]:
    return sorted(REGISTRY, key=lambda item: item.id)


def _basename(command: str) -> str:
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _is_interp(name: str) -> bool:
    return name in INTERP_EXACT or name.startswith(INTERP_PREFIX)


def _class_findings(
    ctx: Context, names: set[str], extra: Callable[[str, CommandItem], bool] | None = None
) -> Iterator[Issue]:
    """Yield one Issue per command whose basename falls in ``names``.

    Each class rule calls this with its own name set, so a command can fire
    several class rules (less is both a pager and a wildcard-escape command)
    without the rules mislabeling each other's findings.
    """
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.negated:
                continue
            for cmd, via in _iter_commands(ctx, spec, item):
                name = _basename(cmd)
                if name in names or (extra is not None and extra(name, item)):
                    yield Issue(
                        message=f"grants {name} (root can be turned into a shell from it)",
                        line=item.lineno,
                        offset=item.offset,
                        length=item.length or len(item.command),
                        saw=item.raw or item.command,
                        where=via,
                    )


def _iter_commands(ctx: Context, spec: UserSpec, item: CommandItem) -> Iterator[tuple[str, str, str]]:
    """Yield (command, where) for the direct command and each alias body."""
    yield item.command, ""
    if item.is_alias:
        for cmd, _args, origin in ctx.expansion(item.alias_name):
            yield cmd, f"via Cmnd_Alias {item.alias_name} (line {origin})"


# ---------------------------------------------------------------- pass 1: user specs


@rule(
    "SUD001",
    "Line does not parse as sudoers",
    "high",
    4,
    1,
    why=(
        "A line visudo would refuse is not audited by sudo: either the file is "
        "rejected wholesale (and every rule in it stops applying) or the line is "
        "silently dropped depending on how it got there. Either way the intent "
        "on that line is not what is in effect."
    ),
    fix="Run `visudo -cf /etc/sudoers` to see the exact error, fix the line, then re-check.",
)
def line_does_not_parse(ctx: Context) -> Iterator[Issue]:
    for error in ctx.app.errors:
        match = re.match(r"^line (\d+): (.*)$", error)
        if not match:
            continue
        lineno = int(match.group(1))
        saw = ctx.app.lines[lineno - 1].strip()[:60] if lineno <= len(ctx.app.lines) else error
        yield Issue(
            message=match.group(2),
            line=lineno,
            offset=ctx.app.line_offsets.get(lineno, 0),
            length=len(saw),
            saw=saw,
        )


@rule(
    "SUD002",
    "NOPASSWD on ALL",
    "critical",
    6,
    1,
    why=(
        "Password-free access to every command is not a grant, it is a login: any process the user owns becomes "
        "root without leaving a sudo-auth trail.",
    ),
    fix="Replace ALL with the exact commands the role needs; keep NOPASSWD off anything that can spawn a shell.",
)
def nopasswd_all(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if not item.has_nopasswd:
                continue
            direct = item.is_all
            via = ""
            if not direct and item.is_alias:
                for cmd, _args, origin in ctx.expansion(item.alias_name):
                    if cmd == "ALL":
                        direct = True
                        via = f"via Cmnd_Alias {item.alias_name} (line {origin})"
                        break
            if direct:
                yield Issue(
                    message="NOPASSWD grants every command without a password prompt",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or 3,
                    saw=item.raw,
                    where=via,
                )


@rule(
    "SUD003",
    "Grant on ALL (every command)",
    "critical",
    6,
    1,
    why=(
        "A command field of ALL grants everything sudo can do; combined with any single misconfigured helper "
        "elsewhere the whole file's intent collapses.",
    ),
    fix="List the commands the role actually runs; `ALL` belongs only in a lab.",
)
def grant_all(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.negated:
                continue
            direct = item.is_all
            via = ""
            if not direct and item.is_alias:
                for cmd, _args, origin in ctx.expansion(item.alias_name):
                    if cmd == "ALL":
                        direct = True
                        via = f"via Cmnd_Alias {item.alias_name} (line {origin})"
                        break
            if direct:
                yield Issue(
                    message="command field is ALL: every command on the host",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or 3,
                    saw=item.raw,
                    where=via,
                )


@rule(
    "SUD004",
    "Grant on a shell",
    "critical",
    6,
    1,
    why="A root shell with no argument restrictions is the grant; every other control on the host is now advisory.",
    fix="Remove it. If an operator needs interactive root, give them the specific commands and a log channel.",
)
def grant_shell(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, SHELLS)


@rule(
    "SUD005",
    "Grant on su or sudo",
    "critical",
    5,
    1,
    why=(
        "su or sudo run as root can start a new session as anyone: the outer grant is an inner grant dispenser and "
        "the audit stops being readable.",
    ),
    fix="Remove the grant; nesting privilege tools under sudo defeats the log trail and the argument checks.",
)
def grant_su(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, SU_SUDO)


@rule(
    "SUD006",
    "Grant on an editor with shell escape",
    "critical",
    5,
    1,
    why=(
        "vi, vim, emacs and friends execute shell commands from inside the editor, so a sudo grant on them is a "
        "sudo grant on a shell.",
    ),
    fix="Use `sudoedit` instead: it copies the file, edits it as the invoking user, and copies back.",
)
def grant_editor(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, EDITORS)


@rule(
    "SUD007",
    "Grant on a pager",
    "high",
    4,
    1,
    why=(
        "less, more and most all run shell commands from within (:!cmd), so a root pager is a root shell with "
        "extra steps.",
    ),
    fix="Remove the grant, or restrict the args to specific safe files if the pager is truly needed.",
)
def grant_pager(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, PAGERS)


@rule(
    "SUD008",
    "Grant on an interpreter",
    "high",
    4,
    1,
    why=(
        "python, perl, awk, sed and the rest execute arbitrary code; -c / -e style flags make a shell of them even "
        "without one.",
    ),
    fix="Grant the specific script with fixed arguments instead of the interpreter.",
)
def grant_interpreter(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, INTERP_EXACT, extra=lambda n, _i: n.startswith(INTERP_PREFIX))


@rule(
    "SUD009",
    "Grant on a file-writing command",
    "high",
    4,
    1,
    why=(
        "cp, mv, tee, dd, install and ln as root can overwrite /etc/shadow, a systemd unit, or a root-owned "
        "binary; the write is the escalation.",
    ),
    fix="Remove the grant, or pin exact source and destination arguments with no wildcards.",
)
def grant_filewrite(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, FILEWRITE)


@rule(
    "SUD010",
    "Grant on a permission-changing command",
    "high",
    4,
    1,
    why=(
        "chmod, chown, chattr and setcap as root let the user take over any binary on the host, including ones "
        "with more grants than this one.",
    ),
    fix="Remove the grant. If a service needs it, scope it to one path with fixed arguments.",
)
def grant_permchange(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, PERMCHANGE)


@rule(
    "SUD011",
    "Grant on a mount command",
    "high",
    4,
    1,
    why=(
        "mount and umount as root allow bind-mounting over system files and mounting attacker-controlled images; "
        "the kernel-side effects are immediate.",
    ),
    fix="Remove the grant, or restrict to specific mount points if the host runs containers that need it.",
)
def grant_mount(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, MOUNTS)


@rule(
    "SUD012",
    "Grant on a debugger or tracer",
    "high",
    3,
    1,
    why=(
        "gdb, strace and ltrace attach to processes and call functions inside them, which is arbitrary code "
        "execution as root.",
    ),
    fix="Remove the grant, or scope to `gdb --batch -ex <fixed-command>` on one pinned binary.",
)
def grant_debugger(ctx: Context) -> Iterator[Issue]:
    yield from _class_findings(ctx, DEBUG)


@rule(
    "SUD013",
    "Grant on find with executable potential",
    "high",
    4,
    1,
    why=(
        "find with unrestricted or wildcard arguments can run -exec on anything it walks; the arguments are chosen "
        "at runtime by the invoker.",
    ),
    fix="Pin the full argument list (paths and predicates) or move the walk into a fixed script.",
)
def grant_find(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.negated:
                continue
            for cmd, via in _iter_commands(ctx, spec, item):
                if _basename(cmd) != "find":
                    continue
                if item.args == "" or "*" in item.args or "-exec" in item.args or "-execdir" in item.args:
                    yield Issue(
                        message=f"grants find with{' unrestricted arguments' if item.args == '' else f' arguments {item.args!r}'} (-exec runs anything it finds)",
                        line=item.lineno,
                        offset=item.offset,
                        length=item.length or len(item.command),
                        saw=item.raw,
                        where=via,
                    )


@rule(
    "SUD014",
    "Grant on a package manager",
    "medium",
    2,
    1,
    why=(
        "apt, dnf, pip and npm install maintainer-controlled code and run maintainer hooks as root; the grant is "
        "as wide as the repository is trusted.",
    ),
    fix="Restrict to pinned packages with fixed arguments, or drive installs from a controlled job instead.",
)
def grant_pkgmgr(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.negated:
                continue
            for cmd, via in _iter_commands(ctx, spec, item):
                if _basename(cmd) in PKGMGR:
                    yield Issue(
                        message=f"grants package manager {cmd} (installs and runs maintainer-controlled code as root)",
                        line=item.lineno,
                        offset=item.offset,
                        length=item.length or len(item.command),
                        saw=item.raw,
                        where=via,
                    )


@rule(
    "SUD015",
    "Wildcard in the command path",
    "high",
    4,
    1,
    why=(
        "`/usr/bin/*` matches more binaries than intended -- and sudo matches the path after sudo's own "
        "resolution, so the gap is whatever the admin forgot exists.",
    ),
    fix="List the exact binary paths; a directory wildcard should never be the grant boundary.",
)
def wildcard_path(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.is_alias or item.negated:
                continue
            if "*" in item.command:
                yield Issue(
                    message=f"command path {item.command!r} contains a wildcard: the grant covers everything it matches",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.command,
                )


@rule(
    "SUD016",
    "Wildcard argument on an argument-escape command",
    "high",
    4,
    1,
    why=(
        "A '*' argument spec on tar, rsync, find, chmod and friends matches any future option the user cares to "
        "type, including ones that execute or overwrite.",
    ),
    fix="Pin the exact arguments. If the set varies, use a wrapper script with an allowlist.",
)
def wildcard_args(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.negated or "*" not in item.args:
                continue
            for cmd, via in _iter_commands(ctx, spec, item):
                if _basename(cmd) in WILD_ESCAPE:
                    yield Issue(
                        message=f"wildcard arguments on {cmd} ({item.args!r}): the invoker chooses the real arguments at runtime",
                        line=item.lineno,
                        offset=item.offset,
                        length=item.length or len(item.command),
                        saw=item.raw,
                        where=via,
                    )


@rule(
    "SUD017",
    "Relative command path",
    "high",
    3,
    1,
    why=(
        "A command without an absolute path is not a command sudo can pin; depending on version it is a syntax "
        "error or it resolves against an environment the user can shape.",
    ),
    fix="Write the full path (`/usr/bin/rsync`, not `rsync`).",
)
def relative_path(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.is_alias or item.negated or not item.command:
                continue
            if item.command.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", item.command):
                continue
            yield Issue(
                message=f"command {item.command!r} is not an absolute path",
                line=item.lineno,
                offset=item.offset,
                length=item.length or len(item.command),
                saw=item.command,
            )


@rule(
    "SUD018",
    "Command under a world-writable directory",
    "critical",
    6,
    1,
    why=(
        "A grant on a path inside /tmp, /var/tmp or /dev/shm grants whatever binary the user manages to place "
        "there; the file is not root's.",
    ),
    fix="Move the tool into a root-owned directory and grant that path.",
)
def tmp_path(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.is_alias or item.negated:
                continue
            lowered = item.command.lower()
            if lowered in TMP_EXACT or lowered.startswith(TMP_PREFIXES):
                yield Issue(
                    message=f"command path {item.command!r} lives under a world-writable directory",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.command,
                )


@rule(
    "SUD019",
    "SETENV tag on a grant",
    "high",
    3,
    1,
    why=(
        "SETENV lets the invoker set arbitrary environment variables for the target process, which is one "
        "LD_PRELOAD away from code execution as root.",
    ),
    fix="Drop the SETENV tag; export what is genuinely needed via `Defaults env_keep` with a named list.",
)
def setenv_tag(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.has_setenv:
                yield Issue(
                    message="SETENV tag allows arbitrary environment variables for the target command",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or 6,
                    saw=item.raw,
                )


@rule(
    "SUD020",
    "Runas spec allows impersonating any user",
    "high",
    3,
    1,
    why=(
        "(ALL) means the command can run as any account, so the grant also reaches files and processes owned by "
        "service users nobody audits.",
    ),
    fix="Name the exact runas users; `(root)` when only root is meant.",
)
def runas_all(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if "ALL" in item.runas_users:
                yield Issue(
                    message="runas user list is ALL: the command can run as any account",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.raw,
                )


@rule(
    "SUD021",
    "Runas spec allows any group",
    "medium",
    2,
    1,
    why=(
        "(root:ALL) hands over group membership of any group, which on many hosts is one docker or shadow group "
        "away from root.",
    ),
    fix="Name the exact runas groups.",
)
def runas_group_all(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if "ALL" in item.runas_groups:
                yield Issue(
                    message="runas group list is ALL: the command can run with any group",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.raw,
                )


@rule(
    "SUD022",
    "Spec applies to every account",
    "high",
    3,
    1,
    why=(
        "A user field of ALL includes service and hidden accounts; their processes now hold a sudo grant nobody "
        "meant them to have.",
    ),
    fix="List the accounts or groups explicitly; exclude service users with `Defaults:user !<grant>` if ALL must stay.",
)
def user_all(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        if "ALL" in spec.users:
            yield Issue(
                message="user list is ALL: every account on the host holds this grant",
                line=spec.lineno,
                offset=spec.offset,
                length=len(spec.raw.strip()),
                saw=spec.raw.strip()[:60],
            )


@rule(
    "SUD023",
    "Shell metacharacters in a fixed argument spec",
    "medium",
    2,
    1,
    why=(
        "Arguments are matched literally, but combined with any wildcard or a quoting bug the metacharacters "
        "become an injection surface the file's author did not intend.",
    ),
    fix="Keep argument specs plain paths and flags; move shell logic into a fixed script.",
)
def metachar_args(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_all or item.is_alias:
                continue
            hit = next((ch for ch in METACHARS if ch in item.args), None)
            if hit:
                yield Issue(
                    message=f"argument spec {item.args!r} contains {hit!r}",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.raw,
                )


@rule(
    "SUD024",
    "Deny-list entry inside a broad grant",
    "medium",
    2,
    1,
    why=(
        "A `!command` inside an otherwise wide spec is a deny-list; the user can copy the binary elsewhere and run "
        "that, since the deny names one path only.",
    ),
    fix="Invert it: start from an empty grant and allow-list the commands that are actually needed.",
)
def deny_in_broad(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        broad = any(i.is_all or "*" in i.command or "*" in i.args for i in spec.items)
        if not broad:
            continue
        for item in spec.items:
            if item.negated:
                yield Issue(
                    message=f"deny entry {item.raw!r} inside a broad grant: the command can be copied or linked and run from another path",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.raw,
                )


@rule(
    "SUD025",
    "NOPASSWD tag cascades to later commands in the list",
    "medium",
    2,
    1,
    why=(
        "A tag applies to every command that follows it in the same list until an opposite tag appears, so a "
        "NOPASSWD meant for one command quietly covers the rest.",
    ),
    fix="Repeat the PASSWD tag on the commands that must still prompt, or split the list.",
)
def nopasswd_cascade(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        armed_at = None
        for item in spec.items:
            if "NOPASSWD" in item.tags:
                armed_at = item
                continue
            if "PASSWD" in item.tags:
                armed_at = None
                continue
            if armed_at is not None:
                yield Issue(
                    message=f"NOPASSWD set at line {armed_at.lineno} also applies to this command",
                    line=item.lineno,
                    offset=item.offset,
                    length=item.length or len(item.command),
                    saw=item.raw,
                )


# ---------------------------------------------------------------- pass 1: Defaults


@rule(
    "SUD026",
    "env_reset disabled",
    "high",
    3,
    1,
    why=(
        "Without env_reset the invoking user's whole environment reaches the root process, and with it any "
        "variable the target command trusts.",
    ),
    fix="Remove the `!env_reset` line; keep env_reset and add a named env_keep list if needed.",
)
def env_reset_off(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        if "env_reset" in line.negated_names:
            yield Issue(
                message="Defaults !env_reset passes the caller's environment into root processes",
                line=line.lineno,
                offset=line.offset,
                length=len(line.raw.strip()),
                saw=line.raw.strip()[:60],
            )


@rule(
    "SUD027",
    "timestamp_timeout set to never expire",
    "high",
    3,
    1,
    why=(
        "A negative timestamp_timeout means one password prompt ever; from then on the account is a passwordless "
        "sudo until logout, and lock-screen does not reset it.",
    ),
    fix="Set a small positive value (the default 15 minutes) or drop the line.",
)
def timeout_never(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        for name, op, value in line.params:
            if name != "timestamp_timeout" or op != "=":
                continue
            try:
                minutes = float(value)
            except ValueError:
                continue
            if minutes < 0:
                yield Issue(
                    message=f"timestamp_timeout={value}: the password prompt effectively never returns",
                    line=line.lineno,
                    offset=line.offset,
                    length=len(line.raw.strip()),
                    saw=line.raw.strip()[:60],
                )


@rule(
    "SUD028",
    "Password prompt targets the wrong account",
    "medium",
    2,
    1,
    why=(
        "rootpw, targetpw or runaspw make sudo prompt for a password other than the invoker's, which turns "
        "shoulder-surfing and weak target passwords into the whole control.",
    ),
    fix="Remove the line; keep prompting for the invoking user's own password.",
)
def wrong_password(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        for name, _op, _value in line.params:
            if name in ("rootpw", "targetpw", "runaspw") and name not in line.negated_names:
                yield Issue(
                    message=f"{name} enabled: sudo accepts the wrong account's password",
                    line=line.lineno,
                    offset=line.offset,
                    length=len(line.raw.strip()),
                    saw=line.raw.strip()[:60],
                )


@rule(
    "SUD029",
    "secure_path disabled",
    "medium",
    2,
    1,
    why=(
        "Without secure_path, `sudo somecmd` resolves against the caller's PATH, so a wrapper in the user's home "
        "becomes the root command.",
    ),
    fix="Remove the `!secure_path` line, or set an explicit `secure_path=...` list.",
)
def secure_path_off(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        if "secure_path" in line.negated_names:
            yield Issue(
                message="Defaults !secure_path: commands resolve against the caller's PATH",
                line=line.lineno,
                offset=line.offset,
                length=len(line.raw.strip()),
                saw=line.raw.strip()[:60],
            )


@rule(
    "SUD030",
    "use_pty disabled",
    "note",
    1,
    1,
    why=(
        "Without a pty the sudo session shares the caller's terminal, which weakens session recording (iolog) and "
        "lets TTY tricks survive into the root process.",
    ),
    fix="Remove the `!use_pty` line unless a specific job depends on it.",
)
def use_pty_off(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        if "use_pty" in line.negated_names:
            yield Issue(
                message="Defaults !use_pty: the root process shares the caller's terminal",
                line=line.lineno,
                offset=line.offset,
                length=len(line.raw.strip()),
                saw=line.raw.strip()[:60],
            )


@rule(
    "SUD031",
    "requiretty disabled",
    "note",
    1,
    1,
    why=(
        "Without requiretty sudo also works from cron and daemons where no human is watching the terminal; every "
        "other control should assume that path exists.",
    ),
    fix="Acceptable for CI hosts; otherwise remove the `!requiretty` line.",
)
def requiretty_off(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        if "requiretty" in line.negated_names:
            yield Issue(
                message="Defaults !requiretty: sudo also runs from headless contexts",
                line=line.lineno,
                offset=line.offset,
                length=len(line.raw.strip()),
                saw=line.raw.strip()[:60],
            )


@rule(
    "SUD032",
    "env_keep keeps a dangerous variable",
    "high",
    3,
    1,
    why=(
        "LD_PRELOAD, PYTHONPATH, BASH_ENV and friends let the invoking user steer what the root process loads and "
        "executes before its main() runs.",
    ),
    fix="Drop the variable from env_keep; export it from inside the fixed wrapper script instead.",
)
def env_keep_dangerous(ctx: Context) -> Iterator[Issue]:
    for line in ctx.app.defaults:
        for name, op, value in line.params:
            if name != "env_keep" or op not in ("=", "+=") or not value:
                continue
            parts = re.split(r"[ :,]+", value)
            hit = [p for p in parts if p.upper() in DANGEROUS_ENV]
            if hit:
                yield Issue(
                    message=f"env_keep passes {', '.join(hit)} into root processes",
                    line=line.lineno,
                    offset=line.offset,
                    length=len(line.raw.strip()),
                    saw=line.raw.strip()[:60],
                )


# ---------------------------------------------------------------- pass 2: aliases


@rule(
    "SUD033",
    "Alias name is not uppercase",
    "medium",
    2,
    2,
    why=(
        "sudoers only resolves alias names in uppercase; a lowercase definition is dead text and every spec "
        "referencing it silently fails to match.",
    ),
    fix="Rename the alias to uppercase letters, digits and underscores.",
)
def alias_lowercase(ctx: Context) -> Iterator[Issue]:
    for atype, table in ctx.app.aliases.items():
        for alias in table.values():
            if not alias.name.isupper():
                yield Issue(
                    message=f"{atype} {alias.name!r} is not all-uppercase: sudo will never resolve it",
                    line=alias.lineno,
                    offset=alias.offset,
                    length=len(alias.name),
                    saw=alias.name,
                )


@rule(
    "SUD034",
    "Alias referenced but never defined",
    "high",
    3,
    2,
    why=(
        "A spec pointing at an alias that does not exist matches nothing: the admin believes access is granted (or "
        "denied) while sudo ignores the line.",
    ),
    fix="Define the alias or remove the reference; `visudo -cf` catches this for the file it checks.",
)
def alias_undefined(ctx: Context) -> Iterator[Issue]:
    defined = ctx.app.aliases
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_alias and item.alias_name not in defined.get("Cmnd_Alias", {}):
                yield Issue(
                    message=f"Cmnd_Alias {item.alias_name!r} is referenced but never defined",
                    line=item.lineno,
                    offset=item.offset,
                    length=len(item.alias_name),
                    saw=item.alias_name,
                )
        for user in spec.users:
            if re.match(r"^[A-Z][A-Z0-9_]*$", user) and user != "ALL" and user not in defined.get("User_Alias", {}):
                yield Issue(
                    message=f"User_Alias {user!r} is referenced but never defined",
                    line=spec.lineno,
                    offset=spec.offset,
                    saw=user,
                )
        for host in spec.hosts:
            if re.match(r"^[A-Z][A-Z0-9_]*$", host) and host != "ALL" and host not in defined.get("Host_Alias", {}):
                yield Issue(
                    message=f"Host_Alias {host!r} is referenced but never defined",
                    line=spec.lineno,
                    offset=spec.offset,
                    saw=host,
                )
        for item in spec.items:
            for runas in item.runas_users:
                if (
                    re.match(r"^[A-Z][A-Z0-9_]*$", runas)
                    and runas != "ALL"
                    and runas not in defined.get("Runas_Alias", {})
                ):
                    yield Issue(
                        message=f"Runas_Alias {runas!r} is referenced but never defined",
                        line=item.lineno,
                        offset=item.offset,
                        saw=runas,
                    )


@rule(
    "SUD035",
    "Alias defined but never used",
    "low",
    1,
    2,
    why=(
        "An unused alias is either a leftover from a removed grant (check where its members went) or a spelling "
        "difference between the definition and the spec that meant to use it.",
    ),
    fix="Delete it, or fix the reference that misspells it.",
)
def alias_unused(ctx: Context) -> Iterator[Issue]:
    referenced: set[tuple[str, str]] = set()
    for spec in ctx.specs():
        for item in spec.items:
            if item.is_alias:
                referenced.add(("Cmnd_Alias", item.alias_name))
            for runas in item.runas_users:
                if re.match(r"^[A-Z][A-Z0-9_]*$", runas) and runas != "ALL":
                    referenced.add(("Runas_Alias", runas))
        for user in spec.users:
            if re.match(r"^[A-Z][A-Z0-9_]*$", user) and user != "ALL":
                referenced.add(("User_Alias", user))
        for host in spec.hosts:
            if re.match(r"^[A-Z][A-Z0-9_]*$", host) and host != "ALL":
                referenced.add(("Host_Alias", host))
    for atype, table in ctx.app.aliases.items():
        for alias in table.values():
            if (atype, alias.name) not in referenced:
                yield Issue(
                    message=f"{atype} {alias.name} is defined but never referenced",
                    line=alias.lineno,
                    offset=alias.offset,
                    length=len(alias.name),
                    saw=alias.name,
                )


@rule(
    "SUD036",
    "Alias defined twice",
    "medium",
    2,
    2,
    why=(
        "visudo refuses duplicate alias definitions; in a file assembled from snippets or automation the second "
        "definition wins or breaks visudo, and either outcome is a surprise.",
    ),
    fix="Keep one definition; if two snippets must merge, rename one.",
)
def alias_duplicate(ctx: Context) -> Iterator[Issue]:
    for note in ctx.app.notes:
        match = re.match(r"^line (\d+): (\w+ \S+) defined again \(first at line (\d+)\)$", note)
        if not match:
            continue
        lineno = int(match.group(1))
        yield Issue(
            message=f"{match.group(2)} defined again (first at line {match.group(3)})",
            line=lineno,
            offset=ctx.app.line_offsets.get(lineno, 0),
            saw=ctx.app.lines[lineno - 1].strip()[:60] if lineno <= len(ctx.app.lines) else note,
        )


@rule(
    "SUD037",
    "Circular Cmnd_Alias",
    "high",
    3,
    2,
    why=(
        "An alias that eventually includes itself has no fixed membership; expansion either loops forever or stops "
        "wherever the resolver gave up, and the audit's view of what is granted is wrong either way.",
    ),
    fix="Break the cycle: aliases should form a tree, not a graph with a loop.",
)
def alias_circular(ctx: Context) -> Iterator[Issue]:
    from .parser import parse_item

    table = ctx.app.aliases.get("Cmnd_Alias", {})
    for alias in table.values():
        visited = {alias.name}
        frontier = [alias]
        cycle = False
        while frontier and not cycle:
            current = frontier.pop()
            for member in current.members:
                item = parse_item(member)
                if not item.is_alias:
                    continue
                nxt = table.get(item.alias_name)
                if nxt is None:
                    continue
                if nxt.name in visited:
                    cycle = True
                    break
                visited.add(nxt.name)
                frontier.append(nxt)
        if cycle:
            yield Issue(
                message=f"Cmnd_Alias {alias.name} participates in a reference cycle ({' -> '.join(sorted(visited))})",
                line=alias.lineno,
                offset=alias.offset,
                length=len(alias.name),
                saw=alias.name,
            )


@rule(
    "SUD038",
    "User_Alias contains ALL",
    "high",
    3,
    2,
    why=(
        "An alias whose members include ALL makes every spec that uses it a grant to every account, and the word "
        "ALL no longer stands out where the grant is written.",
    ),
    fix="Remove ALL from the alias; keep grants explicit at the spec.",
)
def user_alias_all(ctx: Context) -> Iterator[Issue]:
    for alias in ctx.app.aliases.get("User_Alias", {}).values():
        if "ALL" in alias.members:
            yield Issue(
                message=f"User_Alias {alias.name} contains ALL: every spec using it covers every account",
                line=alias.lineno,
                offset=alias.offset,
                length=len(alias.name),
                saw=alias.name,
            )


@rule(
    "SUD039",
    "Cmnd_Alias contains ALL",
    "high",
    3,
    2,
    why=(
        "An alias whose members include ALL turns any use of it into an everything grant; combined with a NOPASSWD "
        "tag elsewhere this is the classic accidental root login.",
    ),
    fix="Remove ALL from the alias; keep the boundary in the spec where it is visible.",
)
def cmnd_alias_all(ctx: Context) -> Iterator[Issue]:
    for alias in ctx.app.aliases.get("Cmnd_Alias", {}).values():
        if any(member.strip().lstrip("!") == "ALL" for member in alias.members):
            yield Issue(
                message=f"Cmnd_Alias {alias.name} contains ALL",
                line=alias.lineno,
                offset=alias.offset,
                length=len(alias.name),
                saw=alias.name,
            )


@rule(
    "SUD041",
    "Include target is a relative path",
    "low",
    1,
    2,
    why=(
        "A relative #include resolves against the sudoers directory, which works on the box where it was written "
        "and silently includes nothing where the layout differs.",
    ),
    fix="Write the absolute path (`/etc/sudoers.d/...`).",
)
def include_relative(ctx: Context) -> Iterator[Issue]:
    for directive in ctx.app.directives:
        if not directive.target.startswith("/"):
            yield Issue(
                message=f"#{directive.kind} target {directive.target!r} is not an absolute path",
                line=directive.lineno,
                offset=directive.offset,
                length=len(directive.target),
                saw=directive.raw.strip()[:60],
            )


# ---------------------------------------------------------------- pass 3: file-wide


@rule(
    "SUD040",
    "Later spec silently replaces an earlier one",
    "high",
    3,
    3,
    why=(
        "sudoers matches the last applicable spec, not the most restrictive: a later line for the same user on the "
        "same host overwrites the earlier grant, which is how a 'temporary widening' becomes permanent and "
        "invisible.",
    ),
    fix="Keep one spec per user per host; if a widening is intentional, write it in one place and comment why.",
)
def duplicate_spec(ctx: Context) -> Iterator[Issue]:
    for spec in ctx.specs():
        for earlier in ctx.specs():
            if earlier.lineno >= spec.lineno:
                continue
            shared_users = _overlap(spec.users, earlier.users)
            shared_hosts = _overlap(spec.hosts, earlier.hosts)
            if shared_users and shared_hosts:
                yield Issue(
                    message=(
                        f"{spec.raw.strip()[:40]!r} matches the same {', '.join(shared_users)} on "
                        f"{', '.join(shared_hosts)} as line {earlier.lineno}; sudo takes the later spec"
                    ),
                    line=spec.lineno,
                    offset=spec.offset,
                    length=len(spec.raw.strip()),
                    saw=spec.raw.strip()[:60],
                    where=f"first spec at line {earlier.lineno}",
                )
                break  # one finding per later spec is enough


def _overlap(a: list[str], b: list[str]) -> list[str]:
    out = [item for item in a if item in b or "ALL" in a + b]
    return out


def executable() -> list[Rule]:
    return _executable()


__all__ = ["REGISTRY", "Rule", "Issue", "Context", "executable"]
