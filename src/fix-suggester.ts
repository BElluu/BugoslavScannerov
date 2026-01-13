import type { ScanResult, Dependency, FixSuggestion } from "./types";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NUGET_API = "https://api.nuget.org/v3-flatcontainer";

export async function suggestFixes(
  vulnerabilities: ScanResult[],
  allDependencies: Dependency[]
): Promise<FixSuggestion[]> {
  const suggestions: FixSuggestion[] = [];
  
  const vulnsByPackage = groupVulnerabilitiesByPackage(vulnerabilities);
  
  for (const [packageName, vulns] of Object.entries(vulnsByPackage)) {
    const dependency = allDependencies.find(d => d.name === packageName);
    if (!dependency) continue;
    
    const suggestion = await generateFixSuggestion(
      packageName,
      dependency.version,
      dependency.ecosystem,
      vulns
    );
    
    suggestions.push(suggestion);
  }
  
  return suggestions.sort((a, b) => {
    // Prioritize: fixable > breaking changes > no fix
    if (a.fixAvailable && !b.fixAvailable) return -1;
    if (!a.fixAvailable && b.fixAvailable) return 1;
    if (a.breakingChange && !b.breakingChange) return 1;
    if (!a.breakingChange && b.breakingChange) return -1;
    return b.vulnerabilityCount - a.vulnerabilityCount;
  });
}

function groupVulnerabilitiesByPackage(
  vulnerabilities: ScanResult[]
): Record<string, ScanResult[]> {
  return vulnerabilities.reduce((acc, vuln) => {
    if (!acc[vuln.package]) acc[vuln.package] = [];
    acc[vuln.package].push(vuln);
    return acc;
  }, {} as Record<string, ScanResult[]>);
}

async function generateFixSuggestion(
  packageName: string,
  currentVersion: string,
  ecosystem: "npm" | "nuget",
  vulnerabilities: ScanResult[]
): Promise<FixSuggestion> {
  const cveIds = vulnerabilities.map(v => v.cveId);
  const vulnerabilityCount = vulnerabilities.length;
  
  const fixedVersions = vulnerabilities
    .map(v => v.fixedVersion)
    .filter((v): v is string => !!v);
  
  if (ecosystem === "npm") {
    return await generateNpmFix(
      packageName,
      currentVersion,
      fixedVersions,
      cveIds,
      vulnerabilityCount
    );
  } else {
    return await generateNuGetFix(
      packageName,
      currentVersion,
      fixedVersions,
      cveIds,
      vulnerabilityCount
    );
  }
}

async function generateNpmFix(
  packageName: string,
  currentVersion: string,
  fixedVersions: string[],
  cveIds: string[],
  vulnerabilityCount: number
): Promise<FixSuggestion> {
  try {
    const response = await fetch(`${NPM_REGISTRY}/${packageName}`);
    
    if (!response.ok) {
      return {
        package: packageName,
        ecosystem: "npm",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "Unable to fetch package information from npm registry",
      };
    }
    
    const data = await response.json();
    const versions = Object.keys((data as any).versions || {});
    
    if (versions.length === 0) {
      return {
        package: packageName,
        ecosystem: "npm",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "No versions available",
      };
    }
    
    const latestVersion = (data as any)["dist-tags"]?.latest; 
    let recommendedVersion: string | undefined;
    
    // Strategy 1: Use fixed version from vulnerability data
    if (fixedVersions.length > 0) {
      recommendedVersion = findBestFixedVersion(fixedVersions, versions);
    }
    
    // Strategy 2: Use latest version
    if (!recommendedVersion && latestVersion) {
      recommendedVersion = latestVersion;
    }
    
    // Strategy 3: Find latest patch/minor in same major
    if (!recommendedVersion) {
      recommendedVersion = findLatestCompatibleVersion(currentVersion, versions);
    }
    
    if (!recommendedVersion) {
      return {
        package: packageName,
        ecosystem: "npm",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "No safe version found",
      };
    }

    // Check if recommended version is actually newer than current
    if (!isNewerVersion(currentVersion, recommendedVersion)) {
      return {
        package: packageName,
        ecosystem: "npm",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "Current version is already up to date or newer than fixed version",
      };
    }

    const isBreaking = isBreakingChange(currentVersion, recommendedVersion);

    return {
      package: packageName,
      ecosystem: "npm",
      currentVersion,
      recommendedVersion,
      fixAvailable: true,
      command: `npm install ${packageName}@${recommendedVersion}`,
      cveIds,
      vulnerabilityCount,
      breakingChange: isBreaking,
      reason: isBreaking
        ? "⚠️  Breaking change - review changelog before updating"
        : "✅ Safe to update (patch/minor version)",
    };
  } catch (error) {
    return {
      package: packageName,
      ecosystem: "npm",
      currentVersion,
      fixAvailable: false,
      cveIds,
      vulnerabilityCount,
      reason: `Error fetching package info: ${error}`,
    };
  }
}

async function generateNuGetFix(
  packageName: string,
  currentVersion: string,
  fixedVersions: string[],
  cveIds: string[],
  vulnerabilityCount: number
): Promise<FixSuggestion> {
  try {
    const normalizedName = packageName.toLowerCase();
    const response = await fetch(
      `${NUGET_API}/${normalizedName}/index.json`
    );
    
    if (!response.ok) {
      return {
        package: packageName,
        ecosystem: "nuget",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "Unable to fetch package information from NuGet",
      };
    }
    
    const data = await response.json();
    const versions = (data as any).versions || [];
    
    if (versions.length === 0) {
      return {
        package: packageName,
        ecosystem: "nuget",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "No versions available",
      };
    }
    
    let recommendedVersion: string | undefined;
    
    // Strategy 1: Use fixed version from vulnerability data
    if (fixedVersions.length > 0) {
      recommendedVersion = findBestFixedVersion(fixedVersions, versions);
    }
    
    // Strategy 2: Use latest version
    if (!recommendedVersion) {
      recommendedVersion = versions[versions.length - 1];
    }
    
    // Strategy 3: Find latest compatible version
    if (!recommendedVersion) {
      recommendedVersion = findLatestCompatibleVersion(currentVersion, versions);
    }
    
    if (!recommendedVersion) {
      return {
        package: packageName,
        ecosystem: "nuget",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "No safe version found",
      };
    }

    // Check if recommended version is actually newer than current
    if (!isNewerVersion(currentVersion, recommendedVersion)) {
      return {
        package: packageName,
        ecosystem: "nuget",
        currentVersion,
        fixAvailable: false,
        cveIds,
        vulnerabilityCount,
        reason: "Current version is already up to date or newer than fixed version",
      };
    }

    const isBreaking = isBreakingChange(currentVersion, recommendedVersion);

    return {
      package: packageName,
      ecosystem: "nuget",
      currentVersion,
      recommendedVersion,
      fixAvailable: true,
      command: `dotnet add package ${packageName} --version ${recommendedVersion}`,
      cveIds,
      vulnerabilityCount,
      breakingChange: isBreaking,
      reason: isBreaking
        ? "⚠️  Breaking change - review changelog before updating"
        : "✅ Safe to update (patch/minor version)",
    };
  } catch (error) {
    return {
      package: packageName,
      ecosystem: "nuget",
      currentVersion,
      fixAvailable: false,
      cveIds,
      vulnerabilityCount,
      reason: `Error fetching package info: ${error}`,
    };
  }
}

function findBestFixedVersion(
  fixedVersions: string[],
  availableVersions: string[]
): string | undefined {
  const sortedFixed = fixedVersions
    .filter(v => availableVersions.includes(v))
    .sort(compareVersions);

  // Return the HIGHEST (latest) fixed version, not the lowest
  return sortedFixed[sortedFixed.length - 1];
}

function findLatestCompatibleVersion(
  currentVersion: string,
  availableVersions: string[]
): string | undefined {
  const current = parseVersion(currentVersion);
  if (!current) return availableVersions[availableVersions.length - 1];
  
  const compatible = availableVersions
    .filter(v => {
      const parsed = parseVersion(v);
      return parsed && parsed.major === current.major;
    })
    .sort(compareVersions);
  
  return compatible[compatible.length - 1];
}

function isBreakingChange(current: string, target: string): boolean {
  const currentParsed = parseVersion(current);
  const targetParsed = parseVersion(target);

  if (!currentParsed || !targetParsed) return true;

  return targetParsed.major > currentParsed.major;
}

function isNewerVersion(current: string, target: string): boolean {
  const currentParsed = parseVersion(current);
  const targetParsed = parseVersion(target);

  if (!currentParsed || !targetParsed) return false;

  if (targetParsed.major !== currentParsed.major) {
    return targetParsed.major > currentParsed.major;
  }
  if (targetParsed.minor !== currentParsed.minor) {
    return targetParsed.minor > currentParsed.minor;
  }
  return targetParsed.patch > currentParsed.patch;
}

function parseVersion(version: string): { major: number; minor: number; patch: number } | null {
  const cleaned = version.replace(/^[v^~>=<]/, "");
  const parts = cleaned.split(".").map(p => parseInt(p.split("-")[0], 10));
  
  if (parts.length < 2 || parts.some(isNaN)) return null;
  
  return {
    major: parts[0] || 0,
    minor: parts[1] || 0,
    patch: parts[2] || 0,
  };
}

function compareVersions(a: string, b: string): number {
  const aParsed = parseVersion(a);
  const bParsed = parseVersion(b);
  
  if (!aParsed || !bParsed) return 0;
  
  if (aParsed.major !== bParsed.major) return aParsed.major - bParsed.major;
  if (aParsed.minor !== bParsed.minor) return aParsed.minor - bParsed.minor;
  return aParsed.patch - bParsed.patch;
}