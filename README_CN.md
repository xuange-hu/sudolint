# sudolint

[![CI](https://github.com/xuange-hu/sudolint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/sudolint/actions/workflows/ci.yml)
[![version-0.1.0](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md)
[![Python >= 3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/sudolint/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-41-red)](#规则表)

**用攻击者的方式审计 `/etc/sudoers`。** 零依赖、证据式、三遍扫描：这一行的授权、它背后的别名、以及"后者覆盖前者"的文件级陷阱。

```console
$ pip install .
$ sudolint demo
$ sudolint scan /etc/sudoers
```

三步中的第二步不需要你自己的文件：`demo` 内置三份 sudoers 语料，合计触发全部 41 条规则。

## 为什么再造一个 linter

sudoers 不是声明式白名单，逐行检查器会在三个地方读错：

1. **授权的真实宽度取决于别名展开。** `NOPASSWD: PAGER_CMDS` 看起来无害，直到 `Cmnd_Alias PAGER_CMDS = /usr/bin/less`——而 `less` 能起 shell。sudolint 展开每个 Cmnd_Alias，按展开后的内容分类，而不是按字面。
2. **标签会级联。** `NOPASSWD: cmd1, cmd2` 对**两条**命令都生效；显式 `PASSWD:` 才会重置。sudolint 计算每条命令实际生效的标签，而不是只看写在一起的那条。
3. **后写的匹配规范赢。** 同一用户同一主机的后一行会静默替换前一行——"临时放宽"就是这样变成永久且不可见的。

## 能查出什么（41 条规则，3 遍扫描）

| 遍 | 读什么 | 例子 |
|---|---|---|
| 1 — 行 | 授权、标签、runas、Defaults | NOPASSWD 配 ALL；授权 shell / 编辑器 / 分页器 / 解释器；root 身份跑 `cp`/`chmod`/`mount`；路径与参数通配符；`(ALL)` runas；`!env_reset`；`timestamp_timeout=-1`；`env_keep += "LD_PRELOAD"` |
| 2 — 别名 | 定义 vs 实际 | 引用了未定义的别名；定义了没人用；重复定义；Cmnd_Alias 循环引用；别名里藏 `ALL`；sudo 永远解析不了的小写别名 |
| 3 — 文件 | 行与行之间 | 后写规范静默替换同一用户同一主机的先前授权 |

每条结论都带行号、字节偏移和引发它的原始字节：

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

`--fail-on` 把报告变成门禁：`sudolint scan /etc/sudoers --fail-on high` 在达到 high 及以上时退出 1——否则 0，读不进文件是 2。`--sarif` 输出 SARIF 2.1.0，可直接上传 GitHub code scanning，字节偏移与终端报告一致。

## MCP server

六个工具给 Claude Code / Cursor / Cline 用，跑的是和 CLI 同一套引擎：

```console
$ uvx --from "sudolint[mcp]" sudolint-mcp
```

| 工具 | 功能 |
|---|---|
| `sudolint_scan` | 审计单文件或目录树 |
| `sudolint_text` | 直接审计传入文本（PR review、模板文件） |
| `sudolint_rules` | 规则表，可按 stage / severity 过滤 |
| `sudolint_explain` | 单条规则：检测什么、为什么重要、怎么修 |
| `sudolint_sarif` | 单文件的 SARIF 2.1.0 |
| `sudolint_demo` | 跑全部语料，现场验证覆盖率 |

## 规则表

`sudolint rules` 列出全部 41 条（含严重级别与所属遍数）；`sudolint explain SUD004` 打印单条规则的完整 why 与 fix。

## 设计说明

- **零依赖。** 拥有 `/etc/sudoers` 的机器通常全网配置最差，审计必须在它上面能跑。MCP server 是可选 extra（`pip install "sudolint[mcp]"`），惰性导入。
- **证据，不是信任。** 偏移在解析阶段记录，先于任何规则运行。一条指不出具体字节的结论只是观点。
- **输出确定。** 规则按 id 序跑在稳定解析之上；同一文件两次运行逐字节一致，CI 里对报告做 diff 才有意义。
- **宽容解析。** 解析不了的行记录为错误并变成一条结论（`SUD001`）；扫描不会因为半份文件看不懂就拒绝运行。

## 开发

```console
$ git clone https://github.com/xuange-hu/sudolint && cd sudolint
$ pip install -e . pytest
$ python -m pytest -q
$ python -m sudolint demo
```

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
