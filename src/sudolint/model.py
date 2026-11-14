"""What a parsed sudoers file is made of.

Everything carries the line number and the byte offset it came from. A finding
that cannot point at the characters it is talking about is an opinion, so the
offsets are recorded at parse time, before any rule runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

ALIAS_TYPES = ("User_Alias", "Host_Alias", "Cmnd_Alias", "Runas_Alias")

TAGS = (
    "NOPASSWD",
    "PASSWD",
    "SETENV",
    "NOSETENV",
    "LOG_INPUT",
    "NOLOG_INPUT",
    "LOG_OUTPUT",
    "NOLOG_OUTPUT",
    "MAIL",
    "NOMAIL",
    "FOLLOW",
    "NOFOLLOW",
    "EXEC",
    "NOEXEC",
)


@dataclass
class CommandItem:
    """One command inside a user spec's command list."""

    lineno: int
    raw: str
    command: str  # path, alias name, or "ALL" (leading "!" already stripped)
    args: str = ""  # argument spec as written; "" means unrestricted
    args_empty: bool = False  # the "" (empty-string) form
    is_all: bool = False
    is_alias: bool = False
    alias_name: str = ""
    negated: bool = False  # leading "!" deny form
    digest: str = ""  # sha256 digest prefix if present
    runas_users: list[str] = dc_field(default_factory=list)
    runas_groups: list[str] = dc_field(default_factory=list)
    tags: set[str] = dc_field(default_factory=set)  # tags written on this item
    effective_tags: set[str] = dc_field(default_factory=set)  # tags in force after inheritance
    offset: int = 0  # byte offset of the command token within the file
    length: int = 0  # byte length of the command token

    @property
    def has_nopasswd(self) -> bool:
        return "NOPASSWD" in self.effective_tags

    @property
    def has_setenv(self) -> bool:
        return "SETENV" in self.effective_tags

    @property
    def basename(self) -> str:
        return (
            self.command.replace("\\", "/").rsplit("/", 1)[-1].lower() if not self.is_alias and not self.is_all else ""
        )


@dataclass
class UserSpec:
    """One ``users hosts = commands`` line (one colon-separated spec)."""

    lineno: int
    offset: int  # byte offset of the logical line start
    raw: str
    users: list[str]
    hosts: list[str]
    items: list[CommandItem]

    @property
    def label(self) -> str:
        return f"line {self.lineno}: {self.raw.strip()[:48]}"


@dataclass
class AliasDef:
    """One ``Alias_Type NAME = members`` line."""

    type: str
    name: str
    lineno: int
    offset: int
    raw: str
    members: list[str]  # raw member tokens (may reference other aliases)

    @property
    def upper_ok(self) -> bool:
        # sudoers requires alias names to be uppercase letters, digits and
        # underscores, starting with a letter -- a lowercase alias never
        # resolves and the spec silently fails.
        return self.name.isupper() or self.name.replace("_", "").isupper()


@dataclass
class DefaultLine:
    """One ``Defaults ...`` line."""

    lineno: int
    offset: int
    raw: str
    host_qualifier: list[str]  # after "@"
    user_qualifier: list[str]  # after ":"
    user_negated: bool
    runas_qualifier: list[str]  # after ">"
    params: list[tuple[str, str, str]]  # (name, op, value); op in {"", "!", "=", "+=", "-=", "+", "-"}
    negated_names: set[str]


@dataclass
class Directive:
    """A ``#include`` or ``#includedir`` line."""

    lineno: int
    offset: int
    raw: str
    kind: str  # "include" | "includedir"
    target: str
    style: str = "#"  # "#" legacy form, "@" sudo 1.9 form


@dataclass
class App:
    """A whole sudoers file: specs, aliases, defaults, directives, notes."""

    source: str = "<text>"
    lines: list[str] = dc_field(default_factory=list)
    specs: list[UserSpec] = dc_field(default_factory=list)
    aliases: dict[str, dict[str, AliasDef]] = dc_field(default_factory=dict)
    defaults: list[DefaultLine] = dc_field(default_factory=list)
    directives: list[Directive] = dc_field(default_factory=list)
    errors: list[str] = dc_field(default_factory=list)
    notes: list[str] = dc_field(default_factory=list)
    duplicate_aliases: list[tuple[str, str, int, int]] = dc_field(default_factory=list)
    dangling_continuation: bool = False
    size: int = 0
    line_offsets: dict[int, int] = dc_field(default_factory=dict)  # logical line -> byte offset

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def aliases_of(self, alias_type: str) -> dict[str, AliasDef]:
        return self.aliases.get(alias_type, {})


@dataclass
class Finding:
    """One rule's opinion about one place in the file."""

    rule: str
    severity: str  # critical | high | medium | low | note
    message: str
    line: int
    offset: int
    length: int = 0
    saw: str = ""
    fix: str = ""
    where: str = ""
    score: int = 1

    @property
    def end(self) -> int:
        return self.offset + max(self.length, 0)

    def sort_key(self) -> tuple:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
        return (order.get(self.severity, 5), self.line, self.offset, self.rule)


@dataclass
class Report:
    """The result of running every rule over one file."""

    source: str
    app: App
    findings: list[Finding] = dc_field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = dc_field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def risk(self) -> int:
        """0-100. Criticals saturate quickly: three of them is already a bad day."""
        return min(100, sum(f.score for f in self.findings))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.rule] = out.get(finding.rule, 0) + 1
        return out

    @property
    def fired(self) -> set[str]:
        return {f.rule for f in self.findings}
