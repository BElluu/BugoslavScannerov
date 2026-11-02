import type { FailOn, ScanResult, Severity } from "./types.js";

// Unknown severity is ranked as medium: not ignorable, but not alarming either.
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 2 };

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

/** One result per package version and CVE; if several advisories collide, keep the most severe. Sorted by risk. */
export function deduplicateResults(results: ScanResult[]): ScanResult[] {
  const seen = new Map<string, ScanResult>();
  for (const result of results) {
    const key = `${result.package}@${result.version}:${result.cveId}`;
    const existing = seen.get(key);
    if (!existing || severityRank(result.severity) > severityRank(existing.severity)) {
      seen.set(key, result);
    }
  }

  return [...seen.values()].sort(
    (a, b) =>
      Number(b.knownExploited ?? false) - Number(a.knownExploited ?? false) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      (b.cvssScore ?? 0) - (a.cvssScore ?? 0) ||
      a.package.localeCompare(b.package)
  );
}

export function filterSkippedPackages(results: ScanResult[], skipPackages: string[]): ScanResult[] {
  if (skipPackages.length === 0) return results;
  const skip = new Set(skipPackages.map(p => p.toLowerCase()));
  return results.filter(r => !skip.has(r.package.toLowerCase()));
}

export function calculateStats(results: ScanResult[]): Record<Severity, number> {
  const stats: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of results) stats[r.severity]++;
  return stats;
}

/** Whether the scan should fail the build: any result at or above the `failOn` threshold. */
export function shouldFail(results: ScanResult[], failOn: FailOn): boolean {
  if (failOn === "none") return false;
  const threshold = RANK[failOn];
  return results.some(r => severityRank(r.severity) >= threshold);
}
