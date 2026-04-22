import Anthropic from "@anthropic-ai/sdk";
import { toolSchemas, runTool, type Finding, type ToolContext } from "./tools/index.js";

const DEFAULT_MODEL = process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-6";

const SYSTEM_PROMPT = `You are Glasswing, an autonomous defensive security agent.

Your job: given access to a JavaScript/TypeScript codebase, find high-signal security vulnerabilities. You are called by the codebase owner; assume they have authorized this scan.

## How you work

1. Start with \`list_files(path=".")\` to understand the repo layout. If you see a framework (Express, Next.js, NestJS, Hono, Fastify, etc.) prioritize its attack surface first.
2. Form a brief attack-surface plan in your reasoning: where does untrusted input enter? Where does it reach sensitive sinks?
3. Use \`grep\` aggressively to hunt for known-dangerous sinks in the focus classes the user requested. Good starting patterns:
   - RCE: \`\\beval\\b|new Function\\(|child_process|execSync|spawnSync|\\bexec\\(|vm\\.runIn\`
   - SSRF: \`\\bfetch\\(|axios\\.(get|post|request)|http\\.request|got\\(|node-fetch|urlopen\`
   - SQLi: \`\\b(query|raw|\\$queryRaw|exec|execute)\\s*\\(|SELECT .* \\$\\{|pool\\.query\`
   - Path traversal: \`\\b(readFile|createReadStream|sendFile|writeFile|open)\\s*\\(\`
   - Prototype pollution: \`\\bObject\\.assign\\(|merge\\(|_\\.merge|extend\\(|setByPath\`
   - Auth bypass: \`isAdmin|authorize|authenticate|bypass|jwt\\.verify|jwt\\.decode\`
   - XSS: \`innerHTML|dangerouslySetInnerHTML|document\\.write|v-html\`
   - SSRF/open redirect: \`\\bredirect\\(|res\\.redirect\\(|location\\.href\\s*=\`
4. For every hit that looks plausible, \`read_file\` around it (include 30-50 lines of context) and **trace data flow** from the source (request body, query param, env var, file contents) to the sink. If you can't tie untrusted input to the sink, it's not a bug — move on.
5. Call \`record_finding\` the moment you're confident. Do not wait until the end. Each finding must include a concrete proof-of-concept — an example request body or input that triggers it.
6. When you've exhausted the attack surface (or hit ~25 tool calls), call \`finish\` with a summary of what you scanned and concluded.

## Quality bar

- **No speculation.** If you didn't read the sink site, don't report it. Grep hits alone are not findings.
- **No duplicates.** If two lines share the same root cause, report once with both locations.
- **Severity calibration.**
  - critical: unauthenticated RCE, SQLi with direct exfil, full auth bypass
  - high: authenticated RCE, SSRF to internal services, SQLi requiring auth, stored XSS
  - medium: reflected XSS, IDOR with limited impact, missing rate limits on sensitive ops
  - low: info disclosure (stack traces, version headers), logic flaws with narrow impact
  - info: hardening suggestions, defense-in-depth misses
- **Confidence calibration.**
  - high: you've read the sink, traced the source, the PoC is concrete
  - medium: plausible but one hop is inferred
  - low: pattern-matched but unverified; prefer not to report these unless class-critical

## Hard rules

- Only read files inside the scan root. Never attempt to write, execute, or exfiltrate.
- Do not output real credentials, tokens, private keys, or PII found in the code. Reference their location instead.
- If the user requested focus classes, prioritize those but still surface any critical bug you stumble on.
- Keep going until you find real bugs or exhaust sensible leads. "No findings" is a valid outcome if the code is clean.`;

export type RunOptions = {
  root: string;
  focusClasses?: string[];
  maxSteps?: number;
  model?: string;
  onStep?: (event: { step: number; type: string; detail: string }) => void;
};

export type RunResult = {
  findings: Finding[];
  summary: string;
  steps: number;
  stoppedReason: "finished" | "max_steps" | "error";
  error?: string;
};

export async function runGlasswing(opts: RunOptions): Promise<RunResult> {
  const client = new Anthropic();
  const model = opts.model ?? DEFAULT_MODEL;
  const maxSteps = opts.maxSteps ?? 30;
  const ctx: ToolContext = { root: opts.root };

  const focusLine = opts.focusClasses?.length
    ? `Focus vulnerability classes for this scan: ${opts.focusClasses.join(", ")}. Start with these but surface any critical bug you find.`
    : `No focus class specified. Hunt broadly across RCE, SSRF, SQLi, Path Traversal, Prototype Pollution, Auth Bypass, XSS.`;

  const initialUser = `Scan root: ${opts.root}

${focusLine}

Begin with \`list_files(path=".")\`.`;

  const messages: Anthropic.MessageParam[] = [
    { role: "user", content: initialUser },
  ];

  const findings: Finding[] = [];
  let summary = "";
  let step = 0;
  let stoppedReason: RunResult["stoppedReason"] = "max_steps";

  while (step < maxSteps) {
    step++;
    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model,
        max_tokens: 4096,
        system: [
          {
            type: "text",
            text: SYSTEM_PROMPT,
            cache_control: { type: "ephemeral" },
          },
        ],
        tools: toolSchemas as unknown as Anthropic.Tool[],
        messages,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { findings, summary, steps: step, stoppedReason: "error", error: msg };
    }

    // Record the assistant turn
    messages.push({ role: "assistant", content: response.content });

    // Surface any text block to the caller
    for (const block of response.content) {
      if (block.type === "text" && block.text.trim()) {
        opts.onStep?.({
          step,
          type: "thinking",
          detail: block.text.trim().slice(0, 400),
        });
      }
    }

    if (response.stop_reason !== "tool_use") {
      // Model is done without calling finish — treat as finished.
      stoppedReason = "finished";
      if (!summary) {
        const lastText = response.content.find((b) => b.type === "text");
        summary = lastText && lastText.type === "text" ? lastText.text : "Scan ended.";
      }
      break;
    }

    // Run each tool_use block and build the tool_result user turn
    const toolUses = response.content.filter(
      (b): b is Anthropic.ToolUseBlock => b.type === "tool_use"
    );
    const toolResults: Anthropic.ToolResultBlockParam[] = [];

    for (const use of toolUses) {
      const result = await runTool(
        ctx,
        use.name,
        use.input as Record<string, unknown>
      );
      opts.onStep?.({
        step,
        type: `tool:${use.name}`,
        detail: summarizeInput(use.name, use.input),
      });
      toolResults.push({
        type: "tool_result",
        tool_use_id: use.id,
        content: result.content.slice(0, 50_000), // hard cap to protect context
      });
      if (result.finding) findings.push(result.finding);
      if (result.finished) {
        summary = result.finished.summary;
        stoppedReason = "finished";
      }
    }

    messages.push({ role: "user", content: toolResults });

    if (stoppedReason === "finished") break;
  }

  return { findings, summary, steps: step, stoppedReason };
}

function summarizeInput(name: string, input: unknown): string {
  const i = input as Record<string, unknown>;
  switch (name) {
    case "list_files":
      return `path=${i.path ?? "."}`;
    case "read_file":
      return `${i.path}${i.offset ? ` @${i.offset}+${i.limit ?? 2000}` : ""}`;
    case "grep":
      return `/${i.pattern}/ in ${i.path ?? "."}`;
    case "record_finding":
      return `${i.severity} ${i.class} in ${i.file}${i.line ? `:${i.line}` : ""}`;
    case "finish":
      return "done";
    default:
      return JSON.stringify(input).slice(0, 100);
  }
}
