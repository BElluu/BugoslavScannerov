export type Ecosystem = "npm" | "nuget";

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
  scanType: "all" | "fast";
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
  ecosystem: "npm" | "nuget";
  currentVersion: string;
  recommendedVersion?: string;
  fixAvailable: boolean;
  command?: string;
  cveIds: string[];
  vulnerabilityCount: number;
  reason?: string;
  breakingChange?: boolean;
  alternativePackage?: string;
}

export interface PackageVersionInfo {
  name: string;
  version: string;
  publishedAt?: string;
  isDeprecated?: boolean;
}