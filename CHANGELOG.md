# Changelog

## 0.1.0 - 2026-11-14

First release.

- **Three passes, not one grep.** Pass 1 audits each user spec and its command
  classes, tags, runas form and Defaults. Pass 2 resolves aliases (undefined,
  circular, duplicate, unused, `ALL` hidden inside a `Cmnd_Alias`). Pass 3
  reads the file as a whole to catch later specs silently replacing earlier
  ones — sudo applies the **last** match, not the narrowest.
- **41 deterministic rules** with severity, reasoning and a concrete fix.
  `sudolint explain SUD004` prints all three.
- **Evidence first.** Every finding names the file, the line, the byte offset,
  the byte length and the raw text. A dangerous command reached through a
  `Cmnd_Alias` is reported with the alias definition line in `where`.
- **Zero runtime dependencies**, Python 3.10+. CLI, JSON and SARIF 2.1.0 output,
  `--fail-on` exit-code gate (`0` / `1` / `2`), and an optional `mcp` extra
  with 6 tools (pinned `>=1.2,<2`).
- **Built-in demo corpus**: three sudoers files fire all 41 rules; a test pins
  full coverage so a new rule cannot ship without a sample.
- **132 tests** pass on a bare clone with only `pytest` installed; `ruff` clean.
  CI covers Python 3.10-3.13, the MCP tool manifest, the exit-code contract
  with real files, SARIF parsing and a fresh-clone bootstrap.
