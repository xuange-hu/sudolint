"""Parse sudoers text into the model, recording offsets at read time.

The parser is deliberately forgiving: a line it cannot classify is recorded as
an error and the scan continues, because half-reading a sudoers file and
auditing the half you understood is strictly better than refusing to run. The
malformed-line rule turns those errors into findings with evidence.
"""

from __future__ import annotations

import re

from .model import (
    ALIAS_TYPES,
    TAGS,
    AliasDef,
    App,
    CommandItem,
    DefaultLine,
    Directive,
    UserSpec,
)


def _logical_lines(text: str) -> list[tuple[int, int, str]]:
    """Join backslash continuations.

    Returns ``(start_lineno, byte_offset, joined_text)`` triples. The byte
    offset is the offset of the first physical line's start inside the file,
    which is where every finding on this logical line anchors.
    """
    out: list[tuple[int, int, str]] = []
    raw_lines = text.splitlines()
    byte_off = 0
    i = 0
    while i < len(raw_lines):
        lineno = i + 1
        start_off = byte_off
        parts: list[str] = []
        current = raw_lines[i]
        while True:
            # A trailing backslash (optionally followed by blanks) continues
            # the line; sudoers documents this for keeping specs readable.
            stripped = current.rstrip()
            if stripped.endswith("\\") and not stripped.endswith("\\\\"):
                parts.append(stripped[:-1] + " ")
                byte_off += len(raw_lines[i].encode("utf-8")) + 1  # + newline
                i += 1
                if i >= len(raw_lines):
                    break
                current = raw_lines[i]
            else:
                parts.append(current)
                byte_off += len(raw_lines[i].encode("utf-8")) + 1
                i += 1
                break
        out.append((lineno, start_off, "".join(parts)))
        if i > len(raw_lines):
            break
    return out


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split on ``sep`` outside parentheses and double quotes."""
    parts: list[str] = []
    depth = 0
    in_quote = False
    start = 0
    for idx, ch in enumerate(text):
        if ch == '"' and text[idx - 1 : idx] != "\\":
            in_quote = not in_quote
        elif not in_quote and ch == "(":
            depth += 1
        elif not in_quote and ch == ")":
            depth = max(0, depth - 1)
        elif not in_quote and depth == 0 and ch == sep:
            parts.append(text[start:idx])
            start = idx + 1
    parts.append(text[start:])
    return parts


_INCLUDE_RE = re.compile(r"^([#@])\s?(include|includedir)\s+(\S+)\s*$")
_DEFAULTS_RE = re.compile(r"^Defaults([@:!>][^=\s]*)?\s+(.*)$")
_ALIAS_RE = re.compile(r"^(" + "|".join(ALIAS_TYPES) + r")\s+([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$")
_DIGEST_RE = re.compile(r"^sha(224|256|384|512):[0-9a-fA-F]+")


def _parse_item(text: str, lineno: int, line_raw: str, line_off: int) -> CommandItem:
    """Parse one comma-separated command entry, tags and runas included."""
    rest = text.strip()
    negated = False
    while rest.startswith("!"):
        negated = not negated
        rest = rest[1:].lstrip()
    digest = ""
    match = _DIGEST_RE.match(rest)
    if match:
        digest = match.group(0)
        rest = rest[match.end() :].lstrip()
    runas_users: list[str] = []
    runas_groups: list[str] = []
    tags: set[str] = set()
    while True:
        if rest.startswith("("):
            close = rest.find(")")
            inner = rest[1:close] if close > 0 else rest[1:]
            if ":" in inner:
                users_part, groups_part = inner.split(":", 1)
                runas_users = [u.strip() for u in users_part.split(",") if u.strip()]
                runas_groups = [g.strip() for g in groups_part.split(",") if g.strip()]
            else:
                runas_users = [u.strip() for u in inner.split(",") if u.strip()]
            rest = rest[close + 1 :].lstrip() if close > 0 else ""
            continue
        tag_match = re.match(r"^([A-Z_]+)\s*:", rest)
        if tag_match and tag_match.group(1) in TAGS:
            tags.add(tag_match.group(1))
            rest = rest[tag_match.end() :].lstrip()
            continue
        break

    # Command + args: first token is the path, the remainder (as written,
    # quotes preserved) is the argument spec.
    pieces = rest.split(None, 1)
    command = pieces[0] if pieces else ""
    args = pieces[1].strip() if len(pieces) > 1 else ""
    args_empty = args == '""'
    if args_empty:
        args = ""

    is_all = command == "ALL"
    is_alias = bool(re.match(r"^[A-Z][A-Z0-9_]*$", command)) and not is_all

    offset = 0
    length = 0
    if line_raw and command:
        idx = line_raw.find(text.strip())
        if idx < 0:
            idx = line_raw.find(command)
        if idx >= 0:
            offset = (
                line_off
                + len(line_raw[:idx].encode("utf-8"))
                + (len(line_raw[idx:].strip()) - len(line_raw[idx:].lstrip()))
            )
            # Point at the command token itself, after tags/runas.
            cmd_idx = line_raw.find(command, idx)
            if cmd_idx >= 0:
                offset = line_off + len(line_raw[:cmd_idx].encode("utf-8"))
            length = len(command.encode("utf-8"))
    return CommandItem(
        lineno=lineno,
        raw=text.strip(),
        command=command,
        args=args,
        args_empty=args_empty,
        is_all=is_all,
        is_alias=is_alias,
        alias_name=command if is_alias else "",
        negated=negated,
        digest=digest,
        runas_users=runas_users,
        runas_groups=runas_groups,
        tags=tags,
        offset=offset,
        length=length,
    )


def _parse_defaults(line: str, lineno: int, off: int, raw: str) -> DefaultLine:
    match = _DEFAULTS_RE.match(line)
    params: list[tuple[str, str, str]] = []
    negated: set[str] = set()
    host_q: list[str] = []
    user_q: list[str] = []
    user_negated = False
    runas_q: list[str] = []
    if match:
        qualifier = match.group(1) or ""
        rest = match.group(2)
        if qualifier.startswith("@"):
            host_q = [h.strip() for h in qualifier[1:].split(",") if h.strip()]
        elif qualifier.startswith(":"):
            user_q = [u.strip() for u in qualifier[1:].split(",") if u.strip()]
        elif qualifier.startswith("!"):
            user_negated = True
            user_q = [u.strip() for u in qualifier[1:].split(",") if u.strip()]
        elif qualifier.startswith(">"):
            body = qualifier[1:]
            if body.startswith("!"):
                body = body[1:]
            runas_q = [u.strip() for u in body.split(",") if u.strip()]
        for chunk in _split_top_level(rest, ","):
            chunk = chunk.strip()
            if not chunk:
                continue
            neg = False
            while chunk.startswith("!"):
                neg = not neg
                chunk = chunk[1:].lstrip()
            name, op, value = chunk, "", ""
            for candidate in ("-=", "+="):
                if candidate in chunk:
                    name, value = chunk.split(candidate, 1)
                    op = candidate
                    break
            else:
                if "=" in chunk:
                    name, value = chunk.split("=", 1)
                    op = "="
            name = name.strip()
            value = value.strip().strip('"')
            if neg:
                negated.add(name)
            params.append((name, op, value))
    return DefaultLine(
        lineno=lineno,
        offset=off,
        raw=raw,
        host_qualifier=host_q,
        user_qualifier=user_q,
        user_negated=user_negated,
        runas_qualifier=runas_q,
        params=params,
        negated_names=negated,
    )


def _split_specs(text: str) -> list[str]:
    """Split multiple specs on a top-level ``:`` but keep tag colons intact.

    ``NOPASSWD: /bin/ls`` is one spec, not two: the colon belongs to the tag.
    A colon is a separator only when the word in front of it is not a tag.
    """
    parts: list[str] = []
    depth = 0
    in_quote = False
    start = 0
    for idx, ch in enumerate(text):
        if ch == '"' and text[idx - 1 : idx] != "\\":
            in_quote = not in_quote
        elif not in_quote and ch == "(":
            depth += 1
        elif not in_quote and ch == ")":
            depth = max(0, depth - 1)
        elif not in_quote and depth == 0 and ch == ":":
            # A sha256 digest prefix carries its own colon; splitting on it
            # would tear the digest away from the command it pins.
            if re.search(r"sha(?:224|256|384|512)$", text[start:idx]):
                continue
            previous = re.search(r"([A-Z_]+)\s*$", text[start:idx])
            if previous and previous.group(1) in TAGS:
                continue
            parts.append(text[start:idx])
            start = idx + 1
    parts.append(text[start:])
    return parts


_OPPOSITES: dict[str, str] = {}
for _a, _b in (
    ("NOPASSWD", "PASSWD"),
    ("SETENV", "NOSETENV"),
    ("LOG_INPUT", "NOLOG_INPUT"),
    ("LOG_OUTPUT", "NOLOG_OUTPUT"),
    ("MAIL", "NOMAIL"),
    ("FOLLOW", "NOFOLLOW"),
    ("EXEC", "NOEXEC"),
):
    _OPPOSITES[_a] = _b
    _OPPOSITES[_b] = _a


def _inherit_tags(items: list[CommandItem]) -> None:
    """sudoers tags stay in force for later commands in the same spec.

    ``NOPASSWD: /bin/ls, /bin/cat`` exempts both commands, and an explicit
    ``PASSWD:`` turns it off again. Running rules on ``tags`` alone would miss
    every command after the first one.
    """
    state: set[str] = set()
    for item in items:
        for tag in item.tags:
            state.discard(_OPPOSITES.get(tag, ""))
        state.update(item.tags)
        item.effective_tags = set(state)


def _parse_user_spec(line: str, lineno: int, off: int, raw: str, app: App) -> None:
    """Parse ``users hosts = commands`` (with optional ``: more commands``)."""
    eq = _find_top_level_eq(line)
    if eq is None:
        app.errors.append(f"line {lineno}: no '=' in user spec: {line.strip()[:60]}")
        return
    left, right = line[:eq], line[eq + 1 :]
    groups = left.split()
    if len(groups) < 2:
        app.errors.append(f"line {lineno}: user spec needs a user list and a host list before '=': {line.strip()[:60]}")
        return
    users = [u.strip() for u in _split_top_level(" ".join(groups[:-1]), ",") if u.strip()]
    hosts = [h.strip() for h in _split_top_level(groups[-1], ",") if h.strip()]
    segments = _split_specs(right)
    # A colon inside (user:group) stays put; a top-level colon starts a second
    # spec with its own users/hosts on the same line.
    for idx, segment in enumerate(segments):
        if not segment.strip():
            continue
        if idx == 0:
            users_seg, hosts_seg = users, hosts
        else:
            # Second form: "user host = cmds : user host = cmds" is one grammar
            # in sudoers, but the common inline shape is just more commands for
            # the same users. Distinguish: a segment that itself contains '='
            # and two whitespace groups before it is a full spec.
            eq2 = _find_top_level_eq(segment)
            if eq2 is not None:
                seg_left = segment[:eq2]
                seg_groups = seg_left.split()
                if len(seg_groups) >= 2:
                    users_seg = [u.strip() for u in _split_top_level(" ".join(seg_groups[:-1]), ",") if u.strip()]
                    hosts_seg = [h.strip() for h in _split_top_level(seg_groups[-1], ",") if h.strip()]
                    segment = segment[eq2 + 1 :]
                else:
                    users_seg, hosts_seg = users, hosts
            else:
                users_seg, hosts_seg = users, hosts
        items = [_parse_item(part, lineno, raw, off) for part in _split_top_level(segment, ",") if part.strip()]
        if not items:
            app.errors.append(f"line {lineno}: command list is empty: {line.strip()[:60]}")
            return
        _inherit_tags(items)
        app.specs.append(
            UserSpec(
                lineno=lineno,
                offset=off,
                raw=raw,
                users=users_seg,
                hosts=hosts_seg,
                items=items,
            )
        )


def _find_top_level_eq(line: str) -> int | None:
    """The '=' that separates ``users hosts`` from the command list."""
    depth = 0
    in_quote = False
    for idx, ch in enumerate(line):
        if ch == '"' and line[idx - 1 : idx] != "\\":
            in_quote = not in_quote
        elif not in_quote and ch == "(":
            depth += 1
        elif not in_quote and ch == ")":
            depth = max(0, depth - 1)
        elif not in_quote and depth == 0 and ch == "=":
            # sudoers uses "==" never; a single top-level '=' is the separator.
            if idx + 1 < len(line) and line[idx + 1] == "=":
                return None
            return idx
    return None


def parse(text: str, source: str = "<text>") -> App:
    """Parse sudoers text into an :class:`App`."""
    app = App(source=source, lines=text.splitlines(), size=len(text.encode("utf-8")))
    app.dangling_continuation = text.rstrip().endswith("\\")
    for lineno, off, line in _logical_lines(text):
        app.line_offsets[lineno] = off
        stripped = line.strip()
        if not stripped:
            continue
        include = _INCLUDE_RE.match(stripped)
        if include:
            app.directives.append(
                Directive(
                    lineno=lineno,
                    offset=off,
                    raw=line,
                    kind=include.group(2),
                    target=include.group(3),
                    style=include.group(1),
                )
            )
            continue
        if stripped.startswith("#"):
            continue  # comment
        alias_match = _ALIAS_RE.match(stripped)
        if alias_match:
            atype, name, members_text = alias_match.groups()
            members = [m.strip() for m in _split_top_level(members_text, ",") if m.strip()]
            existing = app.aliases.setdefault(atype, {})
            if name in existing:
                # sudoers itself refuses a duplicate alias; a merged-in second
                # definition is at best undefined behaviour, so surface it.
                app.notes.append(f"line {lineno}: {atype} {name} defined again (first at line {existing[name].lineno})")
                app.duplicate_aliases.append((atype, name, existing[name].lineno, lineno))
            else:
                existing[name] = AliasDef(
                    type=atype,
                    name=name,
                    lineno=lineno,
                    offset=off,
                    raw=line,
                    members=members,
                )
            continue
        if re.match(r"^Defaults\b", stripped):
            app.defaults.append(_parse_defaults(stripped, lineno, off, line))
            continue
        _parse_user_spec(stripped, lineno, off, line, app)
    return app


def parse_item(text: str) -> CommandItem:
    """Parse one command-list entry; public wrapper used for alias members.

    A standalone item has no spec to inherit through, so the tags it carries
    are also the tags in force for it.
    """
    item = _parse_item(text, 0, "", 0)
    item.effective_tags = set(item.tags)
    return item


def parse_file(path: str) -> App:
    """Read and parse a sudoers file from disk."""
    from pathlib import Path

    target = Path(path)
    return parse(target.read_text(encoding="utf-8", errors="replace"), source=str(target))


def looks_like_sudoers(text: str) -> bool:
    """Cheap shape check so a directory scan can pick sudoers-shaped files."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return bool(
            _ALIAS_RE.match(stripped) or re.match(r"^Defaults\b", stripped) or _find_top_level_eq(stripped) is not None
        )
    return False


__all__ = ["parse", "parse_file", "looks_like_sudoers"]
