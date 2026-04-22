import type { Finding } from "./tools/index.js";

const SEV_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];

export function renderReport(params: {
  root: string;
  findings: Finding[];
  summary: string;
  model: string;
  steps: number;
  stoppedReason: string;
  startedAt: Date;
  finishedAt: Date;
}): string {
  const { root, findings, summary, model, steps, stoppedReason, startedAt, finishedAt } = params;

  // Sort by severity, then confidence
  const sorted = [...findings].sort((a, b) => {
    const sa = SEV_ORDER.indexOf(a.severity);
    const sb = SEV_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    const ca = ["high", "medium", "low"].indexOf(a.confidence);
    const cb = ["high", "medium", "low"].indexOf(b.confidence);
    return ca - cb;
  });

  const countsBySeverity = SEV_ORDER.reduce<Record<string, number>>((acc, sev) => {
    acc[sev] = sorted.filter((f) => f.severity === sev).length;
    return acc;
  }, {});

  const header = [
    `# Glasswing scan report`,
    ``,
    `**Target:** \`${root}\`  `,
    `**Model:** \`${model}\`  `,
    `**Run:** ${startedAt.toISOString()} → ${finishedAt.toISOString()} (${steps} steps, stopped: ${stoppedReason})`,
    ``,
    `## Summary`,
    ``,
    summary || "_no summary_",
    ``,
    `## Findings by severity`,
    ``,
    SEV_ORDER.filter((s) => countsBySeverity[s] > 0)
      .map((s) => `- **${s}**: ${countsBySeverity[s]}`)
      .join("\n") || "_no findings recorded_",
    ``,
  ].join("\n");

  if (sorted.length === 0) {
    return header + "\n## Detail\n\n_No findings. Either the code is clean or the scan was too shallow — try a higher step budget or a narrower focus._\n";
  }

  const detail = sorted
    .map((f, i) => {
      return [
        `## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`,
        ``,
        `- **Class:** ${f.class}`,
        `- **Location:** \`${f.file}${f.line ? `:${f.line}` : ""}\``,
        `- **Confidence:** ${f.confidence}`,
        ``,
        `### Description`,
        ``,
        f.description,
        ``,
        f.data_flow ? `### Data flow\n\n${f.data_flow}\n` : "",
        f.proof_of_concept ? `### Proof of concept\n\n\`\`\`\n${f.proof_of_concept}\n\`\`\`\n` : "",
        f.fix_suggestion ? `### Suggested fix\n\n${f.fix_suggestion}\n` : "",
      ]
        .filter(Boolean)
        .join("\n");
    })
    .join("\n\n---\n\n");

  return header + "\n## Detail\n\n" + detail + "\n";
}
