#!/usr/bin/env node
import { writeFile, mkdir, access } from "node:fs/promises";
import { resolve, join } from "node:path";
import { runGlasswing } from "./agent.js";
import { renderReport } from "./report.js";

const USAGE = `glasswing — homebrew vulnerability-discovery agent

USAGE
  glasswing scan <path> [options]

OPTIONS
  --focus <classes>     Comma-separated focus classes (e.g. ssrf,sqli,rce,xss,auth).
  --max-steps <n>       Agent step budget. Default 30.
  --model <id>          Anthropic model ID. Default env ANTHROPIC_MODEL, else claude-sonnet-4-6.
  --out <path>          Report output path. Default reports/<timestamp>.md.
  --i-own-this         REQUIRED acknowledgement that you own the code or are authorized to test it.
  --json                Also emit <out>.json with raw findings.
  -h, --help            Show this help.

ENV
  ANTHROPIC_API_KEY     Required.
  ANTHROPIC_MODEL       Optional default model.

EXAMPLES
  glasswing scan ./samples --focus=rce,ssrf --i-own-this
  glasswing scan ~/code/my-api --max-steps=50 --model=claude-opus-4-7 --i-own-this

ETHICS
  This tool tests code you control or have explicit authorization to test.
  Do not scan third-party code without permission. See README.md.`;

type Args = {
  cmd: string | null;
  target: string | null;
  focus: string[] | null;
  maxSteps: number;
  model: string | null;
  out: string | null;
  iOwn: boolean;
  json: boolean;
  help: boolean;
};

function parseArgs(argv: string[]): Args {
  const a: Args = {
    cmd: null,
    target: null,
    focus: null,
    maxSteps: 30,
    model: null,
    out: null,
    iOwn: false,
    json: false,
    help: false,
  };
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") a.help = true;
    else if (arg === "--i-own-this") a.iOwn = true;
    else if (arg === "--json") a.json = true;
    else if (arg.startsWith("--focus=")) a.focus = arg.slice(8).split(",").map((s) => s.trim()).filter(Boolean);
    else if (arg === "--focus") a.focus = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    else if (arg.startsWith("--max-steps=")) a.maxSteps = Number(arg.slice(12));
    else if (arg === "--max-steps") a.maxSteps = Number(argv[++i]);
    else if (arg.startsWith("--model=")) a.model = arg.slice(8);
    else if (arg === "--model") a.model = argv[++i] ?? null;
    else if (arg.startsWith("--out=")) a.out = arg.slice(6);
    else if (arg === "--out") a.out = argv[++i] ?? null;
    else pos.push(arg);
  }
  a.cmd = pos[0] ?? null;
  a.target = pos[1] ?? null;
  return a;
}

function fmtStep(e: { step: number; type: string; detail: string }): string {
  const tag = e.type.padEnd(18);
  const pad = String(e.step).padStart(2, " ");
  return `  [${pad}] ${tag} ${e.detail}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.cmd === null) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 1);
  }
  if (args.cmd !== "scan") {
    console.error(`unknown command: ${args.cmd}`);
    console.error(USAGE);
    process.exit(1);
  }
  if (!args.target) {
    console.error("missing target path");
    console.error(USAGE);
    process.exit(1);
  }
  if (!args.iOwn) {
    console.error(
      "refusing to scan: this tool requires --i-own-this to confirm you own the code or are authorized to test it."
    );
    console.error("see README.md for the ethics policy.");
    process.exit(2);
  }
  if (!process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_AUTH_TOKEN) {
    console.error("ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN for OAuth bearer) is not set.");
    process.exit(3);
  }

  const root = resolve(args.target);
  try {
    await access(root);
  } catch {
    console.error(`target does not exist: ${root}`);
    process.exit(4);
  }

  const model = args.model ?? process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-6";
  console.log(`glasswing: scanning ${root}`);
  console.log(`  model:    ${model}`);
  console.log(`  focus:    ${args.focus?.join(", ") ?? "all classes"}`);
  console.log(`  budget:   ${args.maxSteps} steps`);
  console.log("");

  const startedAt = new Date();
  const result = await runGlasswing({
    root,
    focusClasses: args.focus ?? undefined,
    maxSteps: args.maxSteps,
    model,
    onStep: (e) => console.log(fmtStep(e)),
  });
  const finishedAt = new Date();

  const report = renderReport({
    root,
    findings: result.findings,
    summary: result.summary,
    model,
    steps: result.steps,
    stoppedReason: result.stoppedReason,
    startedAt,
    finishedAt,
  });

  const outPath =
    args.out ??
    join(
      "reports",
      `${startedAt.toISOString().replace(/[:.]/g, "-")}.md`
    );
  await mkdir(resolve(outPath, ".."), { recursive: true });
  await writeFile(outPath, report, "utf8");

  if (args.json) {
    await writeFile(
      outPath + ".json",
      JSON.stringify(
        {
          root,
          model,
          startedAt,
          finishedAt,
          steps: result.steps,
          stoppedReason: result.stoppedReason,
          summary: result.summary,
          findings: result.findings,
          error: result.error,
        },
        null,
        2
      ),
      "utf8"
    );
  }

  console.log("");
  console.log(`glasswing: ${result.findings.length} findings, stopped=${result.stoppedReason}`);
  console.log(`glasswing: report written to ${outPath}`);

  if (result.error) {
    console.error(`glasswing: error: ${result.error}`);
    process.exit(5);
  }
}

main().catch((err) => {
  console.error("fatal:", err instanceof Error ? err.stack ?? err.message : err);
  process.exit(99);
});
