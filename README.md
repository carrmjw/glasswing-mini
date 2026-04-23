# glasswing-mini

An open-source, homebrew take on the idea behind Anthropic's [Project Glasswing](https://www.anthropic.com/glasswing): an autonomous agent that reads a codebase and hunts for security vulnerabilities.

Glasswing proper uses Claude Mythos Preview, an Anthropic-gated model. `glasswing-mini` uses any Claude model you have API access to (defaults to Sonnet 4.6), runs locally, and finds high-signal issues in JS/TS codebases.

It won't match Mythos Preview's ceiling. It will find real bugs in real code, today, for the price of a few cents of tokens per scan.

## What it does

Given a path to a JS/TS repo, the agent:

1. Lists the repo to get the lay of the land
2. Plans the attack surface based on framework + entry points
3. Greps for dangerous sinks (RCE, SSRF, SQLi, path traversal, prototype pollution, auth bypass, XSS)
4. Reads the code around each hit and traces data flow from source (request input, env) to sink
5. Records findings with location, data flow trace, proof-of-concept, and suggested fix
6. Writes a Markdown report

## Install

```bash
git clone https://github.com/carrmjw/glasswing-mini
cd glasswing-mini
npm install
```

Requires Node 20+ and `ripgrep` on `$PATH` (macOS: `brew install ripgrep`).

## Use

```bash
export ANTHROPIC_API_KEY=sk-ant-...
npx tsx src/cli.ts scan ./path/to/your/repo --focus=rce,ssrf,sqli --i-own-this
```

Or build and install globally:

```bash
npm run build
npm link
glasswing scan ./path/to/your/repo --focus=rce,ssrf --i-own-this
```

### Options

| Flag | Default | What |
|---|---|---|
| `--focus <classes>` | all | Comma-separated: `rce,ssrf,sqli,xss,path,proto,auth` |
| `--max-steps <n>` | 30 | Agent step budget (tool calls + think steps) |
| `--model <id>` | `claude-sonnet-4-6` | Anthropic model ID. Use `claude-opus-4-7` for harder targets |
| `--out <path>` | `reports/<ts>.md` | Report output path |
| `--json` | off | Also emit `<out>.json` with raw findings |
| `--i-own-this` | **required** | Ethics gate — see below |

### Example: scan the bundled vulnerable sample

```bash
npx tsx src/cli.ts scan ./samples --focus=rce,ssrf,sqli,path,auth --i-own-this
```

You should see the agent find RCE via `exec("ping ... ${host}")`, SSRF via unvalidated `fetch(url)`, path traversal via `join("/var/docs", name)`, SQLi via template-string query, and the header-based auth bypass.

**Reference output**: [examples/sample-report.md](examples/sample-report.md) — actual report from a clean Sonnet 4.6 run. 5/5 planted bugs found in 8 agent steps / 52s / ~5¢ spend, with zero false positives on the adjacent clean code (`/user-safe`).

## Output

The report is Markdown with:

- One-paragraph summary of what the agent scanned and concluded
- Findings sorted by severity, each with:
  - Class (CWE/OWASP), location (`file:line`), confidence
  - Description, data-flow trace, proof-of-concept, suggested fix

With `--json`, a machine-readable JSON next to the Markdown for CI / issue-filing automation.

## How it works (architecture)

```
src/
  cli.ts       # arg parsing, ethics gate, calls agent, writes report
  agent.ts    # Claude API tool-use loop — system prompt + step limit
  report.ts   # Markdown renderer
  tools/
    index.ts  # list_files, read_file (w/ line numbers), grep (ripgrep), record_finding, finish
```

The agent loop is straightforward Anthropic SDK tool-use: system prompt is cached (`cache_control: ephemeral`), each turn the model gets results of its previous tool calls, and it either calls more tools or stops. Findings are recorded one-at-a-time via the `record_finding` tool instead of waiting until the end — this way, a timeout or token-limit exit still gives you partial results.

Path safety: every tool confines operations to the scan root via a `..`-rejection guard. The agent cannot read outside the path you specify.

## Ethics

**`--i-own-this` is a hard gate.** The tool will not run without it.

Acceptable use:

- Code you wrote or own
- Code where you have explicit written authorization to test (bug bounty in scope, engagement with SoW)
- CTF/vulnerable-by-design codebases (DVWA, WebGoat, OWASP Juice Shop, etc.)

**Not acceptable**:

- Random GitHub repos you don't maintain
- Your employer's code without security team sign-off
- Any target where the scan output could be used to harm users

If you find a bug in software you don't own, follow that project's security policy (SECURITY.md, security@, HackerOne, etc.). Do not publish exploits.

## Limits and honest caveats

- **Sonnet 4.6 is not Mythos Preview.** This tool finds *plausible* vulnerabilities; it will miss hard-to-reach bugs and occasionally false-positive on safe patterns. Always review findings manually before filing.
- **Static only.** No sandbox execution, no fuzzing, no dynamic confirmation. The PoC is generated, not run. A future version could sandbox-verify.
- **JS/TS only.** Extending to Python/Go/Rust is a ~1-day change — most of the codebase is framework-agnostic, but the grep patterns and framework knowledge in the system prompt are JS-shaped.
- **Grep-driven recon.** AST-aware search (ast-grep, Semgrep rules) would be stricter. On the roadmap.

## Roadmap

- [ ] Sandbox PoC verification (Docker-based)
- [ ] AST-grep tool for structural queries
- [ ] `--issue` flag to open GitHub issues from findings
- [ ] Python, Go, Rust ports of the system prompt
- [ ] CVE database cross-reference tool
- [ ] Diff-mode: scan only what changed in a PR

## License

MIT. See [LICENSE](LICENSE).

## Related

- [Anthropic Project Glasswing](https://www.anthropic.com/glasswing) — the industry program this is modeled on
- [Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/) — the model behind it
- [Vulnhuntr](https://github.com/protectai/vulnhuntr) — prior art for Python
- [Google Project Naptime](https://googleprojectzero.blogspot.com/) — the methodology foundation
