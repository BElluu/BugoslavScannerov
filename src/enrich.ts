import type { ScanResult } from "./types.js";
import { chunkArray, fetchJson } from "./utils.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const EPSS_CHUNK = 50;

/**
 * Adds exploitation context to results, in place: CISA KEV membership and the EPSS
 * probability. Enrichment is advisory, so a failure here warns and never fails the scan.
 */
export async function enrichResults(results: ScanResult[]): Promise<void> {
  const cves = [...new Set(results.map(r => r.cveId).filter(id => id.startsWith("CVE-")))];
  if (cves.length === 0) return;

  const [kev, epss] = await Promise.all([loadKev(), loadEpss(cves)]);
  for (const result of results) {
    if (kev) result.knownExploited = kev.has(result.cveId);
    const score = epss.get(result.cveId);
    if (score !== undefined) result.epss = score;
  }
}

async function loadKev(): Promise<Set<string> | undefined> {
  try {
    const data = await fetchJson<{ vulnerabilities: Array<{ cveID: string }> }>(KEV_URL);
    return new Set(data.vulnerabilities.map(v => v.cveID));
  } catch (error) {
    console.warn(`⚠️  Could not load CISA KEV catalog: ${error instanceof Error ? error.message : error}`);
    return undefined;
  }
}

async function loadEpss(cves: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  try {
    for (const chunk of chunkArray(cves, EPSS_CHUNK)) {
      const data = await fetchJson<{ data?: Array<{ cve: string; epss: string }> }>(
        `${EPSS_URL}?cve=${chunk.join(",")}`
      );
      for (const row of data.data ?? []) scores.set(row.cve, Number(row.epss));
    }
  } catch (error) {
    console.warn(`⚠️  Could not load EPSS scores: ${error instanceof Error ? error.message : error}`);
  }
  return scores;
}
