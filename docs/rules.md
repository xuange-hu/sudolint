# sudolint rules

41 deterministic rules. Every rule carries a severity, a risk weight,
the reasoning behind it and a concrete fix. Generated from `sudolint.rules.REGISTRY`.

## Pass 1 (32 rules)

### SUD001 — Line does not parse as sudoers

- Severity: **high** (risk weight 4)
- Why: A line visudo would refuse is not audited by sudo: either the file is rejected wholesale (and every rule in it stops applying) or the line is silently dropped depending on how it got there. Either way the intent on that line is not what is in effect.
- Fix: Run `visudo -cf /etc/sudoers` to see the exact error, fix the line, then re-check.

### SUD002 — NOPASSWD on ALL

- Severity: **critical** (risk weight 6)
- Why: ('Password-free access to every command is not a grant, it is a login: any process the user owns becomes root without leaving a sudo-auth trail.',)
- Fix: Replace ALL with the exact commands the role needs; keep NOPASSWD off anything that can spawn a shell.

### SUD003 — Grant on ALL (every command)

- Severity: **critical** (risk weight 6)
- Why: ("A command field of ALL grants everything sudo can do; combined with any single misconfigured helper elsewhere the whole file's intent collapses.",)
- Fix: List the commands the role actually runs; `ALL` belongs only in a lab.

### SUD004 — Grant on a shell

- Severity: **critical** (risk weight 6)
- Why: A root shell with no argument restrictions is the grant; every other control on the host is now advisory.
- Fix: Remove it. If an operator needs interactive root, give them the specific commands and a log channel.

### SUD005 — Grant on su or sudo

- Severity: **critical** (risk weight 5)
- Why: ('su or sudo run as root can start a new session as anyone: the outer grant is an inner grant dispenser and the audit stops being readable.',)
- Fix: Remove the grant; nesting privilege tools under sudo defeats the log trail and the argument checks.

### SUD006 — Grant on an editor with shell escape

- Severity: **critical** (risk weight 5)
- Why: ('vi, vim, emacs and friends execute shell commands from inside the editor, so a sudo grant on them is a sudo grant on a shell.',)
- Fix: Use `sudoedit` instead: it copies the file, edits it as the invoking user, and copies back.

### SUD007 — Grant on a pager

- Severity: **high** (risk weight 4)
- Why: ('less, more and most all run shell commands from within (:!cmd), so a root pager is a root shell with extra steps.',)
- Fix: Remove the grant, or restrict the args to specific safe files if the pager is truly needed.

### SUD008 — Grant on an interpreter

- Severity: **high** (risk weight 4)
- Why: ('python, perl, awk, sed and the rest execute arbitrary code; -c / -e style flags make a shell of them even without one.',)
- Fix: Grant the specific script with fixed arguments instead of the interpreter.

### SUD009 — Grant on a file-writing command

- Severity: **high** (risk weight 4)
- Why: ('cp, mv, tee, dd, install and ln as root can overwrite /etc/shadow, a systemd unit, or a root-owned binary; the write is the escalation.',)
- Fix: Remove the grant, or pin exact source and destination arguments with no wildcards.

### SUD010 — Grant on a permission-changing command

- Severity: **high** (risk weight 4)
- Why: ('chmod, chown, chattr and setcap as root let the user take over any binary on the host, including ones with more grants than this one.',)
- Fix: Remove the grant. If a service needs it, scope it to one path with fixed arguments.

### SUD011 — Grant on a mount command

- Severity: **high** (risk weight 4)
- Why: ('mount and umount as root allow bind-mounting over system files and mounting attacker-controlled images; the kernel-side effects are immediate.',)
- Fix: Remove the grant, or restrict to specific mount points if the host runs containers that need it.

### SUD012 — Grant on a debugger or tracer

- Severity: **high** (risk weight 3)
- Why: ('gdb, strace and ltrace attach to processes and call functions inside them, which is arbitrary code execution as root.',)
- Fix: Remove the grant, or scope to `gdb --batch -ex <fixed-command>` on one pinned binary.

### SUD013 — Grant on find with executable potential

- Severity: **high** (risk weight 4)
- Why: ('find with unrestricted or wildcard arguments can run -exec on anything it walks; the arguments are chosen at runtime by the invoker.',)
- Fix: Pin the full argument list (paths and predicates) or move the walk into a fixed script.

### SUD014 — Grant on a package manager

- Severity: **medium** (risk weight 2)
- Why: ('apt, dnf, pip and npm install maintainer-controlled code and run maintainer hooks as root; the grant is as wide as the repository is trusted.',)
- Fix: Restrict to pinned packages with fixed arguments, or drive installs from a controlled job instead.

### SUD015 — Wildcard in the command path

- Severity: **high** (risk weight 4)
- Why: ("`/usr/bin/*` matches more binaries than intended -- and sudo matches the path after sudo's own resolution, so the gap is whatever the admin forgot exists.",)
- Fix: List the exact binary paths; a directory wildcard should never be the grant boundary.

### SUD016 — Wildcard argument on an argument-escape command

- Severity: **high** (risk weight 4)
- Why: ("A '*' argument spec on tar, rsync, find, chmod and friends matches any future option the user cares to type, including ones that execute or overwrite.",)
- Fix: Pin the exact arguments. If the set varies, use a wrapper script with an allowlist.

### SUD017 — Relative command path

- Severity: **high** (risk weight 3)
- Why: ('A command without an absolute path is not a command sudo can pin; depending on version it is a syntax error or it resolves against an environment the user can shape.',)
- Fix: Write the full path (`/usr/bin/rsync`, not `rsync`).

### SUD018 — Command under a world-writable directory

- Severity: **critical** (risk weight 6)
- Why: ("A grant on a path inside /tmp, /var/tmp or /dev/shm grants whatever binary the user manages to place there; the file is not root's.",)
- Fix: Move the tool into a root-owned directory and grant that path.

### SUD019 — SETENV tag on a grant

- Severity: **high** (risk weight 3)
- Why: ('SETENV lets the invoker set arbitrary environment variables for the target process, which is one LD_PRELOAD away from code execution as root.',)
- Fix: Drop the SETENV tag; export what is genuinely needed via `Defaults env_keep` with a named list.

### SUD020 — Runas spec allows impersonating any user

- Severity: **high** (risk weight 3)
- Why: ('(ALL) means the command can run as any account, so the grant also reaches files and processes owned by service users nobody audits.',)
- Fix: Name the exact runas users; `(root)` when only root is meant.

### SUD021 — Runas spec allows any group

- Severity: **medium** (risk weight 2)
- Why: ('(root:ALL) hands over group membership of any group, which on many hosts is one docker or shadow group away from root.',)
- Fix: Name the exact runas groups.

### SUD022 — Spec applies to every account

- Severity: **high** (risk weight 3)
- Why: ('A user field of ALL includes service and hidden accounts; their processes now hold a sudo grant nobody meant them to have.',)
- Fix: List the accounts or groups explicitly; exclude service users with `Defaults:user !<grant>` if ALL must stay.

### SUD023 — Shell metacharacters in a fixed argument spec

- Severity: **medium** (risk weight 2)
- Why: ("Arguments are matched literally, but combined with any wildcard or a quoting bug the metacharacters become an injection surface the file's author did not intend.",)
- Fix: Keep argument specs plain paths and flags; move shell logic into a fixed script.

### SUD024 — Deny-list entry inside a broad grant

- Severity: **medium** (risk weight 2)
- Why: ('A `!command` inside an otherwise wide spec is a deny-list; the user can copy the binary elsewhere and run that, since the deny names one path only.',)
- Fix: Invert it: start from an empty grant and allow-list the commands that are actually needed.

### SUD025 — NOPASSWD tag cascades to later commands in the list

- Severity: **medium** (risk weight 2)
- Why: ('A tag applies to every command that follows it in the same list until an opposite tag appears, so a NOPASSWD meant for one command quietly covers the rest.',)
- Fix: Repeat the PASSWD tag on the commands that must still prompt, or split the list.

### SUD026 — env_reset disabled

- Severity: **high** (risk weight 3)
- Why: ("Without env_reset the invoking user's whole environment reaches the root process, and with it any variable the target command trusts.",)
- Fix: Remove the `!env_reset` line; keep env_reset and add a named env_keep list if needed.

### SUD027 — timestamp_timeout set to never expire

- Severity: **high** (risk weight 3)
- Why: ('A negative timestamp_timeout means one password prompt ever; from then on the account is a passwordless sudo until logout, and lock-screen does not reset it.',)
- Fix: Set a small positive value (the default 15 minutes) or drop the line.

### SUD028 — Password prompt targets the wrong account

- Severity: **medium** (risk weight 2)
- Why: ("rootpw, targetpw or runaspw make sudo prompt for a password other than the invoker's, which turns shoulder-surfing and weak target passwords into the whole control.",)
- Fix: Remove the line; keep prompting for the invoking user's own password.

### SUD029 — secure_path disabled

- Severity: **medium** (risk weight 2)
- Why: ("Without secure_path, `sudo somecmd` resolves against the caller's PATH, so a wrapper in the user's home becomes the root command.",)
- Fix: Remove the `!secure_path` line, or set an explicit `secure_path=...` list.

### SUD030 — use_pty disabled

- Severity: **note** (risk weight 1)
- Why: ("Without a pty the sudo session shares the caller's terminal, which weakens session recording (iolog) and lets TTY tricks survive into the root process.",)
- Fix: Remove the `!use_pty` line unless a specific job depends on it.

### SUD031 — requiretty disabled

- Severity: **note** (risk weight 1)
- Why: ('Without requiretty sudo also works from cron and daemons where no human is watching the terminal; every other control should assume that path exists.',)
- Fix: Acceptable for CI hosts; otherwise remove the `!requiretty` line.

### SUD032 — env_keep keeps a dangerous variable

- Severity: **high** (risk weight 3)
- Why: ('LD_PRELOAD, PYTHONPATH, BASH_ENV and friends let the invoking user steer what the root process loads and executes before its main() runs.',)
- Fix: Drop the variable from env_keep; export it from inside the fixed wrapper script instead.

## Pass 2 (8 rules)

### SUD033 — Alias name is not uppercase

- Severity: **medium** (risk weight 2)
- Why: ('sudoers only resolves alias names in uppercase; a lowercase definition is dead text and every spec referencing it silently fails to match.',)
- Fix: Rename the alias to uppercase letters, digits and underscores.

### SUD034 — Alias referenced but never defined

- Severity: **high** (risk weight 3)
- Why: ('A spec pointing at an alias that does not exist matches nothing: the admin believes access is granted (or denied) while sudo ignores the line.',)
- Fix: Define the alias or remove the reference; `visudo -cf` catches this for the file it checks.

### SUD035 — Alias defined but never used

- Severity: **low** (risk weight 1)
- Why: ('An unused alias is either a leftover from a removed grant (check where its members went) or a spelling difference between the definition and the spec that meant to use it.',)
- Fix: Delete it, or fix the reference that misspells it.

### SUD036 — Alias defined twice

- Severity: **medium** (risk weight 2)
- Why: ('visudo refuses duplicate alias definitions; in a file assembled from snippets or automation the second definition wins or breaks visudo, and either outcome is a surprise.',)
- Fix: Keep one definition; if two snippets must merge, rename one.

### SUD037 — Circular Cmnd_Alias

- Severity: **high** (risk weight 3)
- Why: ("An alias that eventually includes itself has no fixed membership; expansion either loops forever or stops wherever the resolver gave up, and the audit's view of what is granted is wrong either way.",)
- Fix: Break the cycle: aliases should form a tree, not a graph with a loop.

### SUD038 — User_Alias contains ALL

- Severity: **high** (risk weight 3)
- Why: ('An alias whose members include ALL makes every spec that uses it a grant to every account, and the word ALL no longer stands out where the grant is written.',)
- Fix: Remove ALL from the alias; keep grants explicit at the spec.

### SUD039 — Cmnd_Alias contains ALL

- Severity: **high** (risk weight 3)
- Why: ('An alias whose members include ALL turns any use of it into an everything grant; combined with a NOPASSWD tag elsewhere this is the classic accidental root login.',)
- Fix: Remove ALL from the alias; keep the boundary in the spec where it is visible.

### SUD041 — Include target is a relative path

- Severity: **low** (risk weight 1)
- Why: ('A relative #include resolves against the sudoers directory, which works on the box where it was written and silently includes nothing where the layout differs.',)
- Fix: Write the absolute path (`/etc/sudoers.d/...`).

## Pass 3 (1 rules)

### SUD040 — Later spec silently replaces an earlier one

- Severity: **high** (risk weight 3)
- Why: ("sudoers matches the last applicable spec, not the most restrictive: a later line for the same user on the same host overwrites the earlier grant, which is how a 'temporary widening' becomes permanent and invisible.",)
- Fix: Keep one spec per user per host; if a widening is intentional, write it in one place and comment why.
