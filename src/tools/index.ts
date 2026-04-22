import { readFile } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export type ToolContext = {
  /** Absolute, resolved root. All paths are confined here. */
  root: string;
};

/**
 * Guard: reject any path that tries to escape the scan root via `..` or absolute paths.
 * Returns a safe absolute path, or throws.
 */
function safePath(ctx: ToolContext, input: string): string {
  const abs = resolve(ctx.root, input);
  const rel = relative(ctx.root, abs);
  if (rel.startsWith("..") || rel.startsWith(sep) || rel === "..") {
    throw new Error(`path escapes scan root: ${input}`);
  }
  return abs;
}

export const toolSchemas = [
  {
    name: "list_files",
    description:
      "List files under a relative directory inside the scan root. Returns newline-separated relative paths. Excludes node_modules, .git, dist, build, coverage.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative directory path. Use '.' for root." },
        max_depth: { type: "number", description: "Max depth (default 4).", default: 4 },
      },
      required: ["path"],
    },
  },
  {
    name: "read_file",
    description:
      "Read the contents of a file inside the scan root. Returns the file text prefixed with line numbers. Caps at 2000 lines; use offset/limit for larger files.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative file path." },
        offset: { type: "number", description: "Start line (1-indexed).", default: 1 },
        limit: { type: "number", description: "Max lines to return.", default: 2000 },
      },
      required: ["path"],
    },
  },
  {
    name: "grep",
    description:
      "Ripgrep-backed regex search over files in the scan root. Returns matching lines with file:line:content. Cap 200 hits.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Regex pattern." },
        path: { type: "string", description: "Relative subdir to search (default '.').", default: "." },
        glob: { type: "string", description: "File glob, e.g. '*.{ts,tsx,js,jsx}'.", default: "*.{ts,tsx,js,jsx,mjs,cjs}" },
        case_insensitive: { type: "boolean", default: false },
      },
      required: ["pattern"],
    },
  },
  {
    name: "record_finding",
    description:
      "Record one vulnerability finding. Call this as you discover each issue — you may call it multiple times during the run. Each call is appended to the report.",
    input_schema: {
      type: "object",
      properties: {
        title: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        class: {
          type: "string",
          description: "OWASP/CWE class, e.g. 'CWE-79 XSS', 'SSRF', 'Auth Bypass', 'RCE', 'SQLi', 'Path Traversal', 'Prototype Pollution'.",
        },
        file: { type: "string", description: "Relative file path." },
        line: { type: "number", description: "Line where the sink lives." },
        description: { type: "string", description: "What the bug is, in 2-4 sentences." },
        data_flow: {
          type: "string",
          description: "Source → sink trace. Include file:line for each hop.",
        },
        proof_of_concept: {
          type: "string",
          description: "Concrete input or request that would trigger the bug. Do NOT include real secrets/tokens.",
        },
        fix_suggestion: { type: "string" },
        confidence: { type: "string", enum: ["high", "medium", "low"] },
      },
      required: ["title", "severity", "class", "file", "description", "confidence"],
    },
  },
  {
    name: "finish",
    description:
      "Stop the scan. Call this once you've recorded all findings or determined no vulnerabilities exist. Summarize the attack surface you explored.",
    input_schema: {
      type: "object",
      properties: {
        summary: { type: "string", description: "One paragraph: what you scanned, what you looked for, what you concluded." },
      },
      required: ["summary"],
    },
  },
] as const;

export type Finding = {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  class: string;
  file: string;
  line?: number;
  description: string;
  data_flow?: string;
  proof_of_concept?: string;
  fix_suggestion?: string;
  confidence: "high" | "medium" | "low";
};

export type ToolResult = {
  content: string;
  /** When set, the outer loop exits and uses this as the final report summary. */
  finished?: { summary: string };
  /** When set, the outer loop appends this finding to the report. */
  finding?: Finding;
};

export async function runTool(
  ctx: ToolContext,
  name: string,
  input: Record<string, unknown>
): Promise<ToolResult> {
  try {
    switch (name) {
      case "list_files":
        return { content: await listFiles(ctx, input) };
      case "read_file":
        return { content: await readFileContents(ctx, input) };
      case "grep":
        return { content: await grep(ctx, input) };
      case "record_finding": {
        const f = input as unknown as Finding;
        return {
          content: `recorded: ${f.severity.toUpperCase()} ${f.class} in ${f.file}${f.line ? `:${f.line}` : ""}`,
          finding: f,
        };
      }
      case "finish":
        return {
          content: "scan complete",
          finished: { summary: String(input.summary ?? "") },
        };
      default:
        return { content: `unknown tool: ${name}` };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: `tool error: ${msg}` };
  }
}

async function listFiles(ctx: ToolContext, input: Record<string, unknown>): Promise<string> {
  const dir = safePath(ctx, String(input.path ?? "."));
  const maxDepth = Number(input.max_depth ?? 4);
  // Use find with prune for speed and to dodge node_modules etc.
  const { stdout } = await execFileP(
    "find",
    [
      dir,
      "-maxdepth",
      String(maxDepth),
      "(",
      "-name",
      "node_modules",
      "-o",
      "-name",
      ".git",
      "-o",
      "-name",
      "dist",
      "-o",
      "-name",
      "build",
      "-o",
      "-name",
      "coverage",
      "-o",
      "-name",
      ".next",
      ")",
      "-prune",
      "-o",
      "-type",
      "f",
      "-print",
    ],
    { maxBuffer: 10 * 1024 * 1024 }
  );
  const lines = stdout
    .split("\n")
    .filter(Boolean)
    .map((p) => relative(ctx.root, p))
    .sort();
  const capped = lines.slice(0, 500);
  const note = lines.length > 500 ? `\n[... ${lines.length - 500} more files truncated]` : "";
  return capped.join("\n") + note;
}

async function readFileContents(ctx: ToolContext, input: Record<string, unknown>): Promise<string> {
  const file = safePath(ctx, String(input.path));
  const offset = Math.max(1, Number(input.offset ?? 1));
  const limit = Math.max(1, Math.min(2000, Number(input.limit ?? 2000)));
  const text = await readFile(file, "utf8");
  const lines = text.split("\n");
  const slice = lines.slice(offset - 1, offset - 1 + limit);
  return slice.map((l, i) => `${offset + i}\t${l}`).join("\n");
}

async function grep(ctx: ToolContext, input: Record<string, unknown>): Promise<string> {
  const pattern = String(input.pattern);
  const subdir = safePath(ctx, String(input.path ?? "."));
  const glob = String(input.glob ?? "*.{ts,tsx,js,jsx,mjs,cjs}");
  const caseInsensitive = Boolean(input.case_insensitive);

  const args = [
    "--line-number",
    "--no-heading",
    "--with-filename",
    "--color=never",
    "--max-count=50",
    "--max-columns=300",
    "--glob",
    glob,
    "--glob",
    "!node_modules",
    "--glob",
    "!.git",
    "--glob",
    "!dist",
    "--glob",
    "!build",
    "--glob",
    "!coverage",
  ];
  if (caseInsensitive) args.push("--ignore-case");
  args.push(pattern, subdir);

  try {
    const { stdout } = await execFileP("rg", args, { maxBuffer: 10 * 1024 * 1024 });
    const lines = stdout.split("\n").filter(Boolean);
    const capped = lines.slice(0, 200);
    const note = lines.length > 200 ? `\n[... ${lines.length - 200} more matches truncated]` : "";
    // Rewrite absolute paths to relative
    return (
      capped.map((l) => l.replace(ctx.root + sep, "")).join("\n") + note || "(no matches)"
    );
  } catch (err: unknown) {
    // rg exits 1 on no matches — not an error here.
    const e = err as { code?: number; stdout?: string; stderr?: string };
    if (e.code === 1) return "(no matches)";
    throw err;
  }
}
