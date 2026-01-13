#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { scanWithOSV, scanWithGitHub, scanWithNVD } from "./scanners.js";
import { parseNpmDependencies, parseDotNetDependencies } from "./parsers.js";
import { generateReport } from "./reporter.js";
import type { ScanResult, Config, Dependency } from "./types.js";
import { suggestFixes } from "./fix-suggester.js";

const DEFAULT_CONFIG: Config = {
  scanType: "all",
  sources: ["osv", "github", "nvd"],
  outputFormat: "html",
  outputPath: "",
  githubToken: process.env.GITHUB_TOKEN,
  nvdApiKey: process.env.NVD_API_KEY,
  skipPackages: [],
  suggestFixes: false,
};

async function main() {
  const { values, positionals } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      path: { type: "string", short: "p", default: "." },
      sources: { type: "string", short: "s" },
      output: { type: "string", short: "o" },
      format: { type: "string", short: "f", default: "html" },
      skip: { type: "string" },
      suggestFixes: { type: "boolean", default: false },
      help: { type: "boolean", short: "h" },
      scanType: { type: "string", short: "t" },
    },
    allowPositionals: true,
  });

  if (values.help) {
    printHelp();
    process.exit(0);
  }

  const config: Config = {
    ...DEFAULT_CONFIG,
    scanType: (values.scanType as "all" | "fast") || DEFAULT_CONFIG.scanType,
    sources: values.sources?.split(",") || DEFAULT_CONFIG.sources,
    outputFormat: (values.format as any) || DEFAULT_CONFIG.outputFormat,
    outputPath: values.output || DEFAULT_CONFIG.outputPath,
    skipPackages: values.skip?.split(",").map(pkg => pkg.trim()) || DEFAULT_CONFIG.skipPackages,
    suggestFixes: values.suggestFixes || DEFAULT_CONFIG.suggestFixes,
  };

  const projectPath = values.path || ".";

  console.log("🔍 Bugoslav Skannerov v1.0.0");
  console.log(`📁 Scanning project: ${projectPath}`);
  console.log(`🎯 Sources: ${config.sources.join(", ")}`);
  if (config.skipPackages.length > 0) {
    console.log(`⏭️  Skipping packages: ${config.skipPackages.join(", ")}`);
  }
  console.log("");

  const dependencies = await detectAndParse(projectPath, config.scanType);

  if (dependencies.length === 0) {
    console.error("❌ No dependencies found. Make sure package.json or .csproj files exist.");
    process.exit(1);
  }

  console.log(`📦 Found ${dependencies.length} dependencies to scan\n`);

  const results: ScanResult[] = [];

  if (config.sources.includes("osv")) {
    console.log("🔎 Scanning with OSV...");
    const osvResults = await scanWithOSV(dependencies as Dependency[]);
    results.push(...osvResults);
    console.log(`✓ OSV scan complete: ${osvResults.length} vulnerabilities found\n`);
  }

  if (config.sources.includes("github") && config.githubToken) {
    console.log("🔎 Scanning with GitHub Advisory...");
    const ghResults = await scanWithGitHub(dependencies as Dependency[], config.githubToken);
    results.push(...ghResults);
    console.log(`✓ GitHub scan complete: ${ghResults.length} vulnerabilities found\n`);
  } else if (config.sources.includes("github") && !config.githubToken) {
    console.warn("⚠️  GitHub token not found. Set GITHUB_TOKEN environment variable.\n");
  }

  if (config.sources.includes("nvd")) {
    console.log("🔎 Scanning with NVD...");
    const nvdResults = await scanWithNVD(dependencies as Dependency[], config.nvdApiKey);
    results.push(...nvdResults);
    console.log(`✓ NVD scan complete: ${nvdResults.length} vulnerabilities found\n`);
  }

  const uniqueResults = deduplicateResults(results);
  const filteredResults = filterSkippedPackages(uniqueResults, config.skipPackages);
  const skippedCount = uniqueResults.length - filteredResults.length;
  if (skippedCount > 0) {
    console.log(`⏭️  Skipped ${skippedCount} vulnerabilities due to skipped packages`);
  }
  if (filteredResults.length > 0) {

    let fixSuggestions;
    if (config.suggestFixes && filteredResults.length > 0) {
      console.log("🔧 Analyzing fixes...\n");
      fixSuggestions = await suggestFixes(filteredResults as ScanResult[], dependencies as Dependency[]);
      console.log(`✓ Found ${fixSuggestions.length} fix suggestions\n`);
    }
    const reportPath = await generateReport(filteredResults, config, uniqueResults, fixSuggestions);

    console.log("\n" + "=".repeat(60));
    console.log("📊 SCAN SUMMARY");
    console.log("=".repeat(60));

    const stats = calculateStats(filteredResults);
    console.log(`Total vulnerabilities: ${filteredResults.length || 0}`);
    console.log(`  Critical: ${stats.critical || 0}`);
    console.log(`  High: ${stats.high || 0}`);
    console.log(`  Medium: ${stats.medium || 0}`);
    console.log(`  Low: ${stats.low || 0}`);
    console.log(`\n📄 Report generated: ${reportPath}`);

    if (config.suggestFixes && fixSuggestions && fixSuggestions.length > 0) {
      console.log("\n" + "=".repeat(60));
      console.log("🔧 FIX SUGGESTIONS");
      console.log("=".repeat(60));

      const fixableCount = fixSuggestions.filter((f: any) => f.fixAvailable).length;
      console.log(`${fixableCount} of ${filteredResults.length} vulnerabilities can be fixed\n`);

      // Group by ecosystem
      const npmFixes = fixSuggestions.filter((f: any) => f.ecosystem === "npm" && f.fixAvailable);
      const dotnetFixes = fixSuggestions.filter((f: any) => f.ecosystem === "nuget" && f.fixAvailable);

      if (npmFixes.length > 0) {
        console.log("📦 NPM Packages:");
        npmFixes.slice(0, 5).forEach((fix: any) => {
          console.log(`  ${fix.package}@${fix.currentVersion} → ${fix.recommendedVersion}`);
          console.log(`    ${fix.command}`);
        });
        if (npmFixes.length > 5) {
          console.log(`  ... and ${npmFixes.length - 5} more (see report)`);
        }
        console.log("");
      }

      if (dotnetFixes.length > 0) {
        console.log("📦 .NET Packages:");
        dotnetFixes.slice(0, 5).forEach((fix: any) => {
          console.log(`  ${fix.package} ${fix.currentVersion} → ${fix.recommendedVersion}`);
          console.log(`    ${fix.command}`);
        });
        if (dotnetFixes.length > 5) {
          console.log(`  ... and ${dotnetFixes.length - 5} more (see report)`);
        }
        console.log("");
      }

      console.log("💡 Run these commands to fix vulnerabilities");
      console.log("   Full fix script available in the report");
    }
  }

  if (uniqueResults.length > 0) {
    console.log("\n❌ Build failed due to vulnerabilities matching fail criteria");
    process.exit(1);
  } else {
    console.log("\n✅ No critical vulnerabilities found");
    process.exit(0);
  }
}

async function detectAndParse(projectPath: string, scanType: "all" | "fast") {
  const dependencies: Array<{ name: string; version: string; ecosystem: string }> = [];

  // Check for npm/node project
  const packageJsonPath = join(projectPath, "package.json");
  if (existsSync(packageJsonPath)) {
    console.log("📦 Detected npm project");
    const npmDeps = await parseNpmDependencies(projectPath, scanType);
    dependencies.push(...npmDeps);
  }

  // Check for .NET project
  const csprojFiles = new Bun.Glob("**/*.csproj").scanSync({ cwd: projectPath });
  for (const csproj of csprojFiles) {
    console.log(`📦 Detected .NET project: ${csproj}`);
    const dotnetDeps = await parseDotNetDependencies(join(projectPath, csproj));
    dependencies.push(...dotnetDeps);
  }

  return dependencies;
}

function deduplicateResults(results: ScanResult[]): ScanResult[] {
  const seen = new Map<string, ScanResult>();

  for (const result of results) {
    const key = `${result.package}:${result.cveId}`;
    const existing = seen.get(key);

    if (!existing || severityWeight(result.severity) > severityWeight(existing.severity)) {
      seen.set(key, result);
    }
  }

  for (const [key, result] of seen.entries()) {
    if ((result.severity === "unknown" || result.severity === "moderate") && result.cvssScore) {
      result.severity = calculateSeverityWeight(result.cvssScore) as "critical" | "high" | "medium" | "low" | "moderate" | "unknown";
    }
  }

  let deduplicatedResultList = Array.from(seen.values()).sort((a, b) =>
    severityWeight(b.severity) - severityWeight(a.severity)
  );

  // Filter out vulnerabilities where current version is >= fixed version
  return deduplicatedResultList.filter(result => {
    if (!result.fixedVersion) return true; // No fix version specified, keep it

    // Use semantic version comparison
    const currentVersion = parseVersion(result.version);
    const fixedVersion = parseVersion(result.fixedVersion);

    if (!currentVersion || !fixedVersion) {
      // If we can't parse versions, keep the vulnerability to be safe
      return true;
    }

    // Keep only if current version is less than fixed version
    return isVersionLessThan(currentVersion, fixedVersion);
  });
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

function isVersionLessThan(current: { major: number; minor: number; patch: number }, target: { major: number; minor: number; patch: number }): boolean {
  if (current.major !== target.major) {
    return current.major < target.major;
  }
  if (current.minor !== target.minor) {
    return current.minor < target.minor;
  }
  return current.patch < target.patch;
}

function severityWeight(severity: string): number {
  const weights: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    unknown: 0,
  };
  return weights[severity.toLowerCase()] || 0;
}

function calculateSeverityWeight(cvssScore: number): string {
  if (cvssScore >= 9.0) return "critical";
  if (cvssScore >= 7.0) return "high";
  if (cvssScore >= 4.0) return "medium";
  return "low";
}

function calculateStats(results: ScanResult[]) {
  return results.reduce((acc, r) => {
    const sev = r.severity.toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function filterSkippedPackages(results: ScanResult[], skipPackages: string[]): ScanResult[] {
  if (skipPackages.length === 0) return results;

  const skipSet = new Set(skipPackages.map(p => p.toLowerCase()));
  return results.filter(result => !skipSet.has(result.package.toLowerCase()));
}

function printHelp() {
  console.log(`
Bugoslav Skannerov CLI

Usage: bun run scan [options]

Options:
  -p, --path <path>        Project path to scan (default: current directory)
  -t, --scanType <type>    Scan type: all, fast. all scans all dependencies, fast scans only direct dependencies (default: all)
  -s, --sources <sources>  Comma-separated sources: osv,github,nvd (default: all)
  -o, --output <path>      Output file path (default: bugoslav-scannerov-report)
  -f <format>              Output format: markdown, json, html (default: html)
  --skip <packages>        Comma-separated packages to skip (default: none)
  --suggestFixes           Suggest fixes for vulnerabilities (default: false)
  -h, --help               Show this help message

Environment Variables:
  GITHUB_TOKEN            GitHub personal access token (for GitHub Advisory)
  NVD_API_KEY            NVD API key (optional, increases rate limits)

Examples:
  bun run scan
  bun run scan --path ./my-project --scanType fast
  bun run scan --sources osv,github --format json
  `);
}

main().catch(console.error);