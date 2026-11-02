export type Ecosystem = "npm" | "nuget" | "pypi" | "go" | "cargo";

export type ScanType = "all" | "fast";

/** Where to look up published versions of a package and how to install a specific one. */
export interface Registry {
  /** Published versions, oldest first. */
  versions(name: string): Promise<string[]>;
  command(name: string, version: string): string;
}

export interface EcosystemDefinition {
  id: Ecosystem;
  /** Section title in reports, e.g. "NPM Packages". */
  label: string;
  /** Ecosystem name as used by OSV. */
  osvName: string;
  /** Canonical form of a package name, used to match OSV data against ours. */
  normalizeName(name: string): string;
  /** Finds this ecosystem's manifests below `projectPath` and returns the dependencies; [] if there are none. */
  detect(projectPath: string, scanType: ScanType): Dependency[];
  registry: Registry;
}

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type FailOn = Exclude<Severity, "unknown"> | "none";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

export interface ScanResult {
  package: string;
  version: string;
  ecosystem: Ecosystem;
  /** CVE id when the advisory has one, otherwise the advisory's own id. */
  cveId: string;
  ghsaId?: string;
  severity: Severity;
  summary: string;
  details?: string;
  references: string[];
  cvssScore?: number;
  publishedDate?: string;
  fixedVersion?: string;
  /** Listed in CISA's Known Exploited Vulnerabilities catalog. */
  knownExploited?: boolean;
  /** EPSS probability (0-1) that the CVE is exploited in the next 30 days. */
  epss?: number;
}

export interface Config {
  scanType: ScanType;
  outputFormat: "markdown" | "json" | "html";
  outputPath: string;
  skipPackages: string[];
  suggestFixes: boolean;
  failOn: FailOn;
  enrich: boolean;
}

export interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  withdrawn?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  published?: string;
  database_specific?: {
    severity?: string;
  };
}

export interface FixSuggestion {
  package: string;
  ecosystem: Ecosystem;
  currentVersion: string;
  recommendedVersion?: string;
  fixAvailable: boolean;
  command?: string;
  cveIds: string[];
  vulnerabilityCount: number;
  reason?: string;
  breakingChange?: boolean;
}
