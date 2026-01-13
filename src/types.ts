export interface Dependency {
  name: string;
  version: string;
  ecosystem: "npm" | "nuget";
}

export interface ScanResult {
  package: string;
  version: string;
  ecosystem: string;
  cveId: string;
  ghsaId?: string;
  cveIdFromGhsa?: string;
  severity: "critical" | "high" | "medium" | "low" | "moderate" | "unknown";
  summary: string;
  details?: string;
  references: string[];
  source: "osv" | "github" | "nvd";
  cvssScore?: number;
  publishedDate?: string;
  fixedVersion?: string;
}

export interface Config {
  scanType: "all" | "fast";
  sources: string[];
  outputFormat: "markdown" | "json" | "html";
  outputPath: string;
  githubToken?: string;
  nvdApiKey?: string;
  skipPackages: string[];
  suggestFixes: boolean;
}

export interface OSVVulnerability {
  id: string;
  summary: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
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

export interface NVDResponse {
  vulnerabilities: Array<{
    cve: {
      id: string;
      descriptions: Array<{
        lang: string;
        value: string;
      }>;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: {
            baseScore: number;
            baseSeverity: string;
          };
        }>;
        cvssMetricV2?: Array<{
          cvssData: {
            baseScore: number;
          };
          baseSeverity: string;
        }>;
      };
      references: Array<{
        url: string;
      }>;
      published?: string;
    };
  }>;
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