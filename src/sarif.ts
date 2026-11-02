import type { ScanResult, Severity } from "./types.js";
import { safeUrl } from "./utils.js";

const INFORMATION_URI = "https://github.com/BElluu/BugoslavScannerov";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  unknown: "warning",
  low: "note",
};

// GitHub Code Scanning maps "security-severity" to its own levels: >=9 critical, >=7 high, >=4 medium, else low.
const FALLBACK_SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.5",
};

/** Builds a SARIF 2.1.0 log with one rule per advisory and one result per affected dependency. */
export function toSarif(results: ScanResult[], toolVersion: string) {
  const rules = new Map<string, object>();
  for (const r of results) {
    if (rules.has(r.cveId)) continue;
    const securitySeverity = r.cvssScore?.toFixed(1) ?? FALLBACK_SECURITY_SEVERITY[r.severity];
    rules.set(r.cveId, {
      id: r.cveId,
      name: r.cveId,
      shortDescription: { text: r.summary.slice(0, 200) },
      fullDescription: { text: (r.details ?? r.summary).slice(0, 1000) },
      helpUri: r.references.find(safeUrl),
      defaultConfiguration: { level: LEVEL[r.severity] },
      properties: {
        tags: ["security", "vulnerability", r.ecosystem],
        ...(securitySeverity ? { "security-severity": securitySeverity } : {}),
      },
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Bugoslav Scannerov",
            version: toolVersion,
            informationUri: INFORMATION_URI,
            rules: [...rules.values()],
          },
        },
        results: results.map(r => ({
          ruleId: r.cveId,
          level: LEVEL[r.severity],
          message: {
            text:
              `${r.package}@${r.version} is affected by ${r.cveId}: ${r.summary.replace(/\.?$/, ".")}` +
              (r.fixedVersion ? ` Fixed in ${r.fixedVersion}.` : "") +
              (r.knownExploited ? " Listed in CISA KEV (known to be exploited)." : ""),
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: r.manifest ?? "." },
                region: { startLine: 1 },
              },
            },
          ],
          // Without a line number, the package and advisory identify the alert across runs.
          partialFingerprints: { "bugoslavFinding/v1": `${r.ecosystem}:${r.package}@${r.version}:${r.cveId}` },
          properties: {
            package: r.package,
            version: r.version,
            ecosystem: r.ecosystem,
            severity: r.severity,
            ...(r.fixedVersion ? { fixedVersion: r.fixedVersion } : {}),
            ...(r.knownExploited !== undefined ? { knownExploited: r.knownExploited } : {}),
            ...(r.epss !== undefined ? { epss: r.epss } : {}),
          },
        })),
      },
    ],
  };
}
