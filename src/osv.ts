import type { Dependency, OSVVulnerability, ScanResult, Severity } from "./types.js";
import { cvss3BaseScore, severityFromScore } from "./cvss.js";
import { compareVersions, fixedVersionFromEvents } from "./version.js";
import { chunkArray, fetchJson, mapLimit } from "./utils.js";

const OSV_API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000; // OSV querybatch limit
const DETAIL_CONCURRENCY = 8;

const OSV_ECOSYSTEM: Record<Dependency["ecosystem"], string> = { npm: "npm", nuget: "NuGet" };

interface BatchQuery {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

interface BatchResponse {
  results: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }>;
}

/**
 * Scans dependencies with OSV.dev. Throws if OSV cannot be reached: a failed scan must not
 * look like a clean one.
 */
export async function scanWithOSV(dependencies: Dependency[]): Promise<ScanResult[]> {
  // querybatch returns only advisory ids; details come from /vulns/{id}.
  const idsByDependency = await queryAdvisoryIds(dependencies);

  const uniqueIds = [...new Set(idsByDependency.flatMap(([, ids]) => ids))];
  const details = new Map<string, OSVVulnerability | null>();
  await mapLimit(uniqueIds, DETAIL_CONCURRENCY, async id => {
    details.set(id, await fetchAdvisory(id));
  });

  const results: ScanResult[] = [];
  for (const [dep, ids] of idsByDependency) {
    for (const id of ids) {
      const vuln = details.get(id);
      if (!vuln || vuln.withdrawn) continue;
      results.push(convertOSVToResult(dep, vuln));
    }
  }
  return results;
}

async function queryAdvisoryIds(dependencies: Dependency[]): Promise<Array<[Dependency, string[]]>> {
  const found = dependencies.map(dep => [dep, new Set<string>()] as const);

  let pending = found.map(([dep], index) => ({
    index,
    query: {
      package: { name: dep.name, ecosystem: OSV_ECOSYSTEM[dep.ecosystem] },
      version: dep.version,
    } as BatchQuery,
  }));

  while (pending.length > 0) {
    const next: typeof pending = [];
    for (const chunk of chunkArray(pending, BATCH_SIZE)) {
      const data = await fetchJson<BatchResponse>(`${OSV_API}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: chunk.map(c => c.query) }),
      });
      data.results.forEach((result, i) => {
        const { index, query } = chunk[i];
        for (const vuln of result.vulns ?? []) found[index][1].add(vuln.id);
        if (result.next_page_token) {
          next.push({ index, query: { ...query, page_token: result.next_page_token } });
        }
      });
    }
    pending = next;
  }

  return found.map(([dep, ids]) => [dep, [...ids]]);
}

async function fetchAdvisory(id: string): Promise<OSVVulnerability | null> {
  try {
    return await fetchJson<OSVVulnerability>(`${OSV_API}/vulns/${encodeURIComponent(id)}`);
  } catch (error) {
    if (error instanceof Error && error.message.endsWith("responded 404")) return null;
    throw error;
  }
}

export function convertOSVToResult(dep: Dependency, vuln: OSVVulnerability): ScanResult {
  const { severity, cvssScore } = extractSeverity(vuln);
  const aliases = [vuln.id, ...(vuln.aliases ?? [])];
  const cve = aliases.find(a => a.startsWith("CVE-"));
  const firstLine = vuln.details?.split("\n").find(line => line.trim())?.trim();

  return {
    package: dep.name,
    version: dep.version,
    ecosystem: dep.ecosystem,
    cveId: cve ?? vuln.id,
    ghsaId: aliases.find(a => a.startsWith("GHSA-")),
    severity,
    summary: vuln.summary ?? firstLine ?? vuln.id,
    details: vuln.details,
    references: (vuln.references ?? []).map(r => r.url),
    cvssScore,
    publishedDate: vuln.published,
    fixedVersion: extractFixedVersion(dep, vuln),
  };
}

const DATABASE_SEVERITY: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  medium: "medium",
  low: "low",
};

export function extractSeverity(vuln: OSVVulnerability): { severity: Severity; cvssScore?: number } {
  for (const entry of vuln.severity ?? []) {
    const score = cvss3BaseScore(entry.score);
    if (score !== undefined) return { severity: severityFromScore(score), cvssScore: score };
  }
  const fromDatabase = DATABASE_SEVERITY[vuln.database_specific?.severity?.toLowerCase() ?? ""];
  return { severity: fromDatabase ?? "unknown" };
}

/**
 * Fixed version from the affected range that contains the installed version. An advisory
 * may list several ranges (one per release branch) and several packages; only the matching
 * package and range count.
 */
export function extractFixedVersion(dep: Dependency, vuln: OSVVulnerability): string | undefined {
  const fixes: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (!affected.package) continue;
    if (affected.package.ecosystem.toLowerCase() !== OSV_ECOSYSTEM[dep.ecosystem].toLowerCase()) continue;
    if (affected.package.name.toLowerCase() !== dep.name.toLowerCase()) continue;

    for (const range of affected.ranges ?? []) {
      if (range.type === "GIT") continue;
      const fixed = fixedVersionFromEvents(dep.version, range.events);
      if (fixed) fixes.push(fixed);
    }
  }
  return fixes.length > 0 ? fixes.reduce((min, v) => (compareVersions(v, min) < 0 ? v : min)) : undefined;
}
