import type { FixSuggestion, ScanResult } from "./types.js";
import { ecosystemById } from "./ecosystems/index.js";
import { compareVersions, majorVersion } from "./version.js";
import { mapLimit } from "./utils.js";

// Release versions only: numeric segments, optionally with build metadata (e.g. 1.2.3, 1.2.3+incompatible).
const isStable = (version: string) => /^v?\d+(\.\d+)*(\+[\w.]+)?$/.test(version);

/** One suggestion per vulnerable package version, fixable ones first, then fewest breaking changes. */
export async function suggestFixes(vulnerabilities: ScanResult[]): Promise<FixSuggestion[]> {
  const groups = new Map<string, ScanResult[]>();
  for (const vuln of vulnerabilities) {
    const key = `${vuln.ecosystem}:${vuln.package}@${vuln.version}`;
    groups.set(key, [...(groups.get(key) ?? []), vuln]);
  }

  const suggestions = await mapLimit([...groups.values()], 5, suggestFix);

  return suggestions.sort(
    (a, b) =>
      Number(b.fixAvailable) - Number(a.fixAvailable) ||
      Number(a.breakingChange ?? false) - Number(b.breakingChange ?? false) ||
      b.vulnerabilityCount - a.vulnerabilityCount
  );
}

async function suggestFix(vulns: ScanResult[]): Promise<FixSuggestion> {
  const { package: name, version: currentVersion, ecosystem } = vulns[0];
  const base = {
    package: name,
    ecosystem,
    currentVersion,
    cveIds: vulns.map(v => v.cveId),
    vulnerabilityCount: vulns.length,
  };
  const unfixable = (reason: string): FixSuggestion => ({ ...base, fixAvailable: false, reason });

  const { registry } = ecosystemById(ecosystem);
  let published: string[];
  try {
    published = await registry.versions(name);
  } catch (error) {
    return unfixable(`Unable to fetch package information: ${error instanceof Error ? error.message : error}`);
  }
  if (published.length === 0) return unfixable("No versions available");

  // The advisories' own fix versions: the highest one fixes every advisory (when it is published).
  const advertised = vulns.map(v => v.fixedVersion).filter((v): v is string => !!v);
  const fromAdvisories = published
    .filter(v => advertised.some(f => compareVersions(f, v) === 0))
    .sort(compareVersions)
    .pop();
  const latestStable = published.filter(isStable).sort(compareVersions).pop();

  const recommendedVersion = fromAdvisories ?? latestStable;
  if (!recommendedVersion) return unfixable("No safe version found");
  if (compareVersions(recommendedVersion, currentVersion) <= 0) {
    return unfixable("Current version is already at or above the suggested version");
  }

  const breakingChange = majorVersion(recommendedVersion) > majorVersion(currentVersion);
  const reason = !fromAdvisories
    ? "Advisories list no published fix; latest stable release suggested - verify it resolves the issue"
    : breakingChange
      ? "⚠️  Breaking change - review changelog before updating"
      : "✅ Safe to update (patch/minor version)";

  return {
    ...base,
    recommendedVersion,
    fixAvailable: true,
    command: registry.command(name, recommendedVersion),
    breakingChange,
    reason,
  };
}
