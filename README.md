# sudolint

[![CI](https://github.com/xuange-hu/sudolint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/sudolint/actions/workflows/ci.yml)
[![tests-132%20passing](https://img.shields.io/badge/tests-132%20passing-brightgreen)](https://github.com/xuange-hu/sudolint/actions/workflows/ci.yml)
[![version-0.1.0](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md)
[![Python >= 3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/sudolint/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-41-red)](#the-rule-table)

**Audit `/etc/sudoers` the way an attacker reads it.** Zero dependencies, evidence-first, three passes: the grant on the line, the aliases behind it, and the file-level "last match wins" trap that silently replaces what you wrote.

```console
$ pip install .
$ sudolint demo
$ sudolint scan /etc/sudoers
```

One in three steps runs with no file of your own: `demo` audits three built-in sudoers files that between them trigger all 41 rules.

## Why another linter

sudoers is not a declarative allow-list, and line-by-line checkers misread it in three specific ways:

1. **A grant is only as narrow as the aliases it expands to.** `NOPASSWD: PAGER_CMDS` looks harmless until `Cmnd_Alias PAGER_CMDS = /usr/bin/less` — and `less` runs shell commands. sudolint expands every Cmnd_Alias and classifies the expansion, not the surface.
2. **Tags cascade.** `NOPASSWD: cmd1, cmd2` exempts *both* commands; an explicit `PASSWD:` resets. sudolint computes the tags in force for every command, not just the ones written next to it.
3. **The last matching spec wins.** A later line for the same user on the same host silently replaces the earlier one — which is how a "temporary widening" becomes permanent and invisible.

## What it catches (41 rules, 3 passes)

| Pass | Reads | Examples |
|---|---|---|
| 1 — line | grants, tags, runas, Defaults | NOPASSWD on ALL; grant on a shell / editor / pager / interpreter; `cp`/`chmod`/`mount` as root; wildcards in paths and arguments; `(ALL)` runas; `!env_reset`; `timestamp_timeout=-1`; `env_keep += "LD_PRELOAD"` |
| 2 — aliases | definition vs. reality | alias referenced but never defined; defined but unused; defined twice; circular Cmnd_Alias; `ALL` hidden inside an alias; lowercase names sudo never resolves |
| 3 — file | lines against each other | a later spec silently replacing an earlier one for the same user on the same host |

Every finding carries the line number, a byte offset, and the exact bytes that caused it:

```console
$ sudolint scan /etc/sudoers.d/deploy
/etc/sudoers.d/deploy
  3 finding(s)  critical=1  high=1  medium=1  low=0  note=0  risk=11/100

[critical] SUD004  Grant on a shell
           grants bash (root can be turned into a shell from it)
           line 3, offset 0x2e+9  (via Cmnd_Alias SHELL_CMDS (line 1))
           saw:   SHELL_CMDS
           fix:   Remove it. If an operator needs interactive root, give them the specific commands and a log channel.
```

`--fail-on` turns the report into a gate: `sudolint scan /etc/sudoers --fail-on high` exits 1 when anything at or above `high` is found — 0 otherwise, 2 when the input could not be read. `--sarif` emits SARIF 2.1.0 for a GitHub code-scanning upload, carrying the same byte offsets.

## MCP server

Six tools for Claude Code / Cursor / Cline over the same engine the CLI runs:

```console
$ uvx --from "sudolint[mcp]" sudolint-mcp
```

| Tool | What it does |
|---|---|
| `sudolint_scan` | audit a file or a directory tree |
| `sudolint_text` | audit text passed in directly (PR review, templates) |
| `sudolint_rules` | the rule table, filterable by stage and severity |
| `sudolint_explain` | one rule: detection, why it matters, the fix |
| `sudolint_sarif` | SARIF 2.1.0 for one file |
| `sudolint_demo` | run all corpora, prove the coverage claim |

## The rule table

`sudolint rules` lists all 41 with severity and stage; `sudolint explain SUD004` prints the full why-and-fix for one.

## Design notes

- **Zero dependencies.** The box that owns `/etc/sudoers` is usually the least provisioned one in the estate, and the audit has to run there. The MCP server is an optional extra (`pip install "sudolint[mcp]"`), imported lazily.
- **Evidence, not trust.** Offsets are recorded at parse time, before any rule runs. A finding that cannot point at the characters it is talking about is an opinion.
- **Deterministic output.** Rules run in id order over a stable parse; two runs over one file produce byte-identical reports, so a CI diff of the report means something.
- **Forgiving parser.** A line it cannot classify is recorded as an error and becomes a finding (`SUD001`); the scan never refuses to run because half the file is strange.

## Development

```console
$ git clone https://github.com/xuange-hu/sudolint && cd sudolint
$ pip install -e . pytest
$ python -m pytest -q
$ python -m sudolint demo
```

## License

MIT — see [LICENSE](LICENSE).
