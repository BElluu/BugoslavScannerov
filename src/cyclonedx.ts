import { randomUUID } from "node:crypto";
import type { Dependency, ScanResult } from "./types.js";
import { ecosystemById } from "./ecosystems/index.js";
import { safeUrl } from "./utils.js";

export interface CycloneDxOptions {
  toolVersion: string;
  /** Name of the scanned project, used for the top-level application component. */
  projectName: string;
  now?: Date;
  serialNumber?: string;
}

const purlOf = (dep: Pick<Dependency, "ecosystem" | "name" | "version">) =>
  ecosystemById(dep.ecosystem).purl(dep.name, dep.version);

function advisorySource(id: string): { name: string; url: string } {
  if (id.startsWith("CVE-")) return { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${id}` };
  if (id.startsWith("GHSA-")) return { name: "GitHub Advisory Database", url: `https://github.com/advisories/${id}` };
  return { name: "OSV", url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` };
}

/**
 * Builds a CycloneDX 1.5 SBOM listing every scanned dependency, plus the vulnerabilities found and the
 * components they affect. Vulnerable and clean dependencies are both included: that is what an SBOM is for.
 */
export function toCycloneDx(dependencies: Dependency[], results: ScanResult[], options: CycloneDxOptions) {
  const components = new Map<string, object>();
  for (const dep of dependencies) {
    const purl = purlOf(dep);
    if (components.has(purl)) continue;
    components.set(purl, {
      type: "library",
      "bom-ref": purl,
      name: dep.name,
      version: dep.version,
      purl,
      ...(dep.manifest ? { evidence: { occurrences: [{ location: dep.manifest }] } } : {}),
    });
  }

  const byAdvisory = new Map<string, ScanResult[]>();
  for (const r of results) byAdvisory.set(r.cveId, [...(byAdvisory.get(r.cveId) ?? []), r]);

  const vulnerabilities = [...byAdvisory.entries()].map(([id, affected]) => {
    const first = affected[0];
    const fixes = affected.filter(r => r.fixedVersion).map(r => `${r.package} to ${r.fixedVersion}`);
    const references = [...new Set(affected.flatMap(r => r.references.filter(safeUrl)))].slice(0, 10);
    return {
      id,
      source: advisorySource(id),
      ...(first.ghsaId && first.ghsaId !== id
        ? { references: [{ id: first.ghsaId, source: advisorySource(first.ghsaId) }] }
        : {}),
      ratings: [
        {
          source: { name: "OSV", url: "https://osv.dev" },
          severity: first.severity,
          ...(first.cvssScore !== undefined ? { score: first.cvssScore, method: "CVSSv3" } : {}),
        },
      ],
      description: first.summary,
      ...(first.details ? { detail: first.details.slice(0, 4000) } : {}),
      ...(fixes.length > 0 ? { recommendation: `Upgrade ${fixes.join("; ")}.` } : {}),
      advisories: references.map(url => ({ url })),
      ...(first.publishedDate ? { published: first.publishedDate } : {}),
      affects: [...new Set(affected.map(r => purlOf({ ...r, name: r.package })))].map(ref => ({ ref })),
      ...(first.knownExploited !== undefined || first.epss !== undefined
        ? {
            properties: [
              ...(first.knownExploited !== undefined ? [{ name: "cisa:kev", value: String(first.knownExploited) }] : []),
              ...(first.epss !== undefined ? [{ name: "first:epss", value: String(first.epss) }] : []),
            ],
          }
        : {}),
    };
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: options.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: (options.now ?? new Date()).toISOString(),
      tools: {
        components: [
          {
            type: "application",
            name: "bugoslav-scannerov",
            version: options.toolVersion,
            externalReferences: [{ type: "website", url: "https://github.com/BElluu/BugoslavScannerov" }],
          },
        ],
      },
      component: { type: "application", name: options.projectName },
    },
    components: [...components.values()],
    vulnerabilities,
  };
}
