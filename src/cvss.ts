const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** CVSS 3.1 round-up: smallest number, to one decimal, that is >= input. */
function roundUp(value: number): number {
  const int = Math.round(value * 100000);
  return int % 10000 === 0 ? int / 100000 : (Math.floor(int / 10000) + 1) / 10;
}

/**
 * Computes the CVSS v3.x base score from a vector string such as
 * "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". Returns undefined for anything else
 * (including CVSS v4 and malformed vectors).
 */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;

  const metrics: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [key, value] = part.split(":");
    metrics[key] = value;
  }

  const scopeChanged = metrics.S === "C";
  const av = WEIGHTS.AV[metrics.AV as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[metrics.AC as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[metrics.UI as keyof typeof WEIGHTS.UI];
  const pr = ({ N: 0.85, L: scopeChanged ? 0.68 : 0.62, H: scopeChanged ? 0.5 : 0.27 } as Record<string, number>)[metrics.PR];
  const c = WEIGHTS.CIA[metrics.C as keyof typeof WEIGHTS.CIA];
  const i = WEIGHTS.CIA[metrics.I as keyof typeof WEIGHTS.CIA];
  const a = WEIGHTS.CIA[metrics.A as keyof typeof WEIGHTS.CIA];
  if ([av, ac, ui, pr, c, i, a].some(v => v === undefined) || (metrics.S !== "U" && metrics.S !== "C")) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp(Math.min(raw, 10));
}

export function severityFromScore(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}
