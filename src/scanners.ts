import type { Dependency, ScanResult, OSVVulnerability, NVDResponse } from "./types";
import { chunkArray } from "./utils.js";

const OSV_API = "https://api.osv.dev/v1";
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const GITHUB_API = "https://api.github.com/graphql";

// OSV Scanner
export async function scanWithOSV(dependencies: Dependency[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    const batches = batchByEcosystem(dependencies);

    for (const [ecosystem, deps] of Object.entries(batches)) {
        const queries = deps.map(dep => ({
            package: { name: dep.name, ecosystem: mapEcosystem(ecosystem) },
            version: dep.version,
        }));

        const queryChunks = chunkArray(queries, 100); // ✅ max 100 per request

        for (const chunk of queryChunks) {
            try {
                const response = await fetch(`${OSV_API}/querybatch`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ queries: chunk }),
                });

                if (!response.ok) {
                    console.warn(`OSV API error: ${response.status}`);
                    console.warn(await response.text());
                    continue;
                }

                const data = await response.json();

                for (let i = 0; i < (data as any).results.length; i++) {
                    const result = (data as any).results[i];
                    const dep: Dependency = {
                        name: chunk[i].package.name,
                        ecosystem: chunk[i].package.ecosystem as "npm" | "nuget",
                        version: chunk[i].version,
                    };

                    if (result.vulns && result.vulns.length > 0) {
                        for (const vuln of result.vulns) {
                            results.push(convertOSVToResult(dep, vuln));
                        }
                    }
                }
            } catch (error) {
                console.warn(`Error scanning with OSV: ${error}`);
            }

            // Rate limiting: small delay between batches
            await sleep(100);
        }
    }
    return results;
}

// GitHub Advisory Scanner
export async function scanWithGitHub(dependencies: Dependency[], token?: string): Promise<ScanResult[]> {
    if (!token) return [];

    const results: ScanResult[] = [];

    for (const dep of dependencies) {
        const query = `
      query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
        securityVulnerabilities(first: 10, ecosystem: $ecosystem, package: $package) {
          nodes {
            advisory {
              ghsaId
              summary
              description
              severity
              publishedAt
              references {
                url
              }
              cvss {
                score
              }
            }
            vulnerableVersionRange
            firstPatchedVersion {
              identifier
            }
          }
        }
      }
    `;

        try {
            const response = await fetch(GITHUB_API, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`,
                },
                body: JSON.stringify({
                    query,
                    variables: {
                        ecosystem: mapEcosystemToGitHub(dep.ecosystem),
                        package: dep.name,
                    },
                }),
            });

            if (!response.ok) continue;

            const data = await response.json();
            const vulns = (data as any).data?.securityVulnerabilities?.nodes || [];

            for (const vuln of vulns) {
                // Try to get fixed version from structured data first
                let fixedVersion = vuln.firstPatchedVersion?.identifier;

                // If no fixed version, try parsing description
                if (!fixedVersion && (vuln.advisory.description || vuln.advisory.summary)) {
                    fixedVersion = extractFixedVersionFromDescription(
                        vuln.advisory.description || "",
                        vuln.advisory.summary
                    );
                }

                results.push({
                    package: dep.name,
                    version: dep.version,
                    ecosystem: dep.ecosystem,
                    cveId: vuln.advisory.ghsaId,
                    ghsaId: vuln.advisory.ghsaId,
                    cveIdFromGhsa: vuln.advisory.cveIdFromGhsa,
                    severity: vuln.advisory.severity.toLowerCase(),
                    summary: vuln.advisory.summary,
                    details: vuln.advisory.description,
                    references: vuln.advisory.references.map((r: any) => r.url),
                    source: "github",
                    cvssScore: vuln.advisory.cvss?.score,
                    publishedDate: vuln.advisory.publishedAt,
                    fixedVersion,
                });
            }
        } catch (error) {
            console.warn(`Error scanning ${dep.name} with GitHub: ${error}`);
        }

        // Rate limiting
        await sleep(100);
    }

    return results;
}

// NVD Scanner
export async function scanWithNVD(dependencies: Dependency[], apiKey?: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // NVD requires keyword search, not ideal for package names
    // We'll search for package name and filter results

    for (const dep of dependencies) {
        try {
            const params = new URLSearchParams({
                keywordSearch: dep.name,
                resultsPerPage: "10",
            });

            const headers: Record<string, string> = {};
            if (apiKey) {
                headers["apiKey"] = apiKey;
            }

            const response = await fetch(`${NVD_API}?${params}`, { headers });

            if (!response.ok) {
                if (response.status === 403) {
                    console.warn("NVD API rate limit reached. Consider using an API key.");
                    break;
                }
                continue;
            }

            const data = await response.json() as NVDResponse;

            for (const item of data.vulnerabilities || []) {
                const cve = item.cve;
                const description = cve.descriptions.find(d => d.lang === "en")?.value || "";

                if (description.toLowerCase().includes(dep.name.toLowerCase())) {
                    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];

                    // Try to extract fixed version from description
                    const fixedVersion = extractFixedVersionFromDescription(description);

                    results.push({
                        package: dep.name,
                        version: dep.version,
                        ecosystem: dep.ecosystem,
                        cveId: cve.id,
                        severity: (metrics?.cvssData as any)?.baseSeverity?.toLowerCase() || "unknown",
                        summary: description.substring(0, 200) + (description.length > 200 ? "..." : ""),
                        references: cve.references.map(r => r.url),
                        source: "nvd",
                        cvssScore: metrics?.cvssData?.baseScore,
                        publishedDate: cve.published,
                        fixedVersion,
                    });
                }
            }
        } catch (error) {
            console.warn(`Error scanning ${dep.name} with NVD: ${error}`);
        }

        // NVD has rate limiting, 50/30s with key, 5/30s without
        await sleep(apiKey ? 600 : 6000);
    }

    return results;
}

function batchByEcosystem(deps: Dependency[]): Record<string, Dependency[]> {
    return deps.reduce((acc, dep) => {
        if (!acc[dep.ecosystem]) acc[dep.ecosystem] = [];
        acc[dep.ecosystem].push(dep);
        return acc;
    }, {} as Record<string, Dependency[]>);
}

function mapEcosystem(ecosystem: string): string {
    const mapping: Record<string, string> = {
        npm: "npm",
        nuget: "NuGet",
    };
    return mapping[ecosystem] || ecosystem;
}

function mapEcosystemToGitHub(ecosystem: string): string {
    const mapping: Record<string, string> = {
        npm: "NPM",
        nuget: "NUGET",
    };
    return mapping[ecosystem] || "NPM";
}

function convertOSVToResult(dep: Dependency, vuln: OSVVulnerability): ScanResult {
    const severity = extractSeverity(vuln);
    let fixedVersion = extractFixedVersion(vuln);
    const ghsaId = extractGHSAId(vuln);

    // If no fixed version found in structured data, try parsing description
    if (!fixedVersion && (vuln.details || vuln.summary)) {
        fixedVersion = extractFixedVersionFromDescription(
            vuln.details || "",
            vuln.summary
        );
    }

    return {
        package: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        cveId: vuln.id,
        ghsaId,
        severity,
        summary: vuln.summary,
        details: vuln.details,
        references: vuln.references?.map(r => r.url) || [],
        source: "osv",
        publishedDate: vuln.published,
        fixedVersion,
    };
}

function extractSeverity(vuln: OSVVulnerability): ScanResult["severity"] {
    // Check database_specific first
    if (vuln.database_specific?.severity) {
        return vuln.database_specific.severity.toLowerCase() as any;
    }

    // Check CVSS score
    if (vuln.severity) {
        for (const sev of vuln.severity) {
            if (sev.type === "CVSS_V3") {
                const score = parseFloat(sev.score.split(":")[1] || "0");
                if (score >= 9.0) return "critical";
                if (score >= 7.0) return "high";
                if (score >= 4.0) return "medium";
                return "low";
            }
        }
    }

    return "unknown";
}

function extractFixedVersion(vuln: OSVVulnerability): string | undefined {
    const affected = vuln.affected?.[0];
    if (!affected?.ranges) return undefined;

    for (const range of affected.ranges) {
        for (const event of range.events) {
            if (event.fixed) return event.fixed;
        }
    }

    return undefined;
}

function extractGHSAId(vuln: OSVVulnerability): string | undefined {
  if (vuln.id.startsWith('GHSA-')) {
    return vuln.id;
  }

  if (vuln.aliases) {
    const ghsaAlias = vuln.aliases.find(alias => alias.startsWith('GHSA-'));
    if (ghsaAlias) return ghsaAlias;
  }

  if (vuln.references) {
    for (const ref of vuln.references) {
      const match = ref.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
      if (match) return match[0];
    }
  }

  return undefined;
}

function extractFixedVersionFromDescription(description: string, summary?: string): string | undefined {
  const text = `${description} ${summary || ""}`.toLowerCase();

  // Common patterns for fixed/patched versions
  const patterns = [
    // "Prior to version X.Y.Z" / "prior to X.Y.Z"
    /prior to (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "before version X.Y.Z" / "before X.Y.Z"
    /before (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "versions before X.Y.Z"
    /versions? before (\d+\.\d+(?:\.\d+)?)/i,
    // "lower than version X.Y.Z" / "lower than X.Y.Z"
    /lower than (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "versions lower than X.Y.Z"
    /versions? lower than (\d+\.\d+(?:\.\d+)?)/i,
    // "less than version X.Y.Z" / "less than X.Y.Z"
    /less than (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "versions less than X.Y.Z"
    /versions? less than (\d+\.\d+(?:\.\d+)?)/i,
    // "fixed in version X.Y.Z" / "fixed in X.Y.Z"
    /fixed in (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "patched in version X.Y.Z" / "patched in X.Y.Z"
    /patched in (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "versions < X.Y.Z"
    /versions? < (\d+\.\d+(?:\.\d+)?)/i,
    // "< X.Y.Z"
    /< (\d+\.\d+(?:\.\d+)?)/i,
    // "upgrade to X.Y.Z"
    /upgrade to (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
    // "update to X.Y.Z"
    /update to (?:version )?(\d+\.\d+(?:\.\d+)?)/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  return undefined;
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}