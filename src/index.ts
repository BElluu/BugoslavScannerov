#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { scanWithOSV } from "./osv.js";
import { enrichResults } from "./enrich.js";
import { dedupeDependencies, findCsprojFiles, parseDotNetDependencies, parseNpmDependencies } from "./parsers.js";
import { generateReport } from "./reporter.js";
import { calculateStats, deduplicateResults, filterSkippedPackages, shouldFail } from "./results.js";
import { suggestFixes } from "./fix-suggester.js";
import type { Config, Dependency, FailOn, FixSuggestion } from "./types.js";

const VERSION = "1.0.0";

const FORMATS = ["markdown", "json", "html"] as const;
const SCAN_TYPES = ["all", "fast"] as const;
const FAIL_ON = ["none", "low", "medium", "high", "critical"] as const;

class UsageError extends Error {}

function oneOf<T extends string>(name: string, value: string, allowed: readonly T[]): T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new UsageError(`Invalid --${name} "${value}". Expected one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function parseConfig(): { config: Config; projectPath: string } | undefined {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      path: { type: "string", short: "p", default: "." },
      output: { type: "string", short: "o", default: "bugoslav-scannerov-report" },
      format: { type: "string", short: "f", default: "html" },
      scanType: { type: "string", short: "t", default: "all" },
      skip: { type: "string" },
      suggestFixes: { type: "boolean", default: false },
      failOn: { type: "string", default: "low" },
      noEnrich: { type: "boolean", default: false },
      help: { type: "boolean", short: "h" },
    },
  });

  if (values.help) {
    printHelp();
    return undefined;
  }

  return {
    projectPath: values.path!,
    config: {
      scanType: oneOf("scanType", values.scanType!, SCAN_TYPES),
      outputFormat: oneOf("format", values.format!, FORMATS),
      outputPath: values.output!,
      skipPackages: values.skip?.split(",").map(p => p.trim()).filter(Boolean) ?? [],
      suggestFixes: values.suggestFixes!,
      failOn: oneOf("failOn", values.failOn!, FAIL_ON) as FailOn,
      enrich: !values.noEnrich,
    },
  };
}

async function main(): Promise<number> {
  const parsed = parseConfig();
  if (!parsed) return 0;
  const { config, projectPath } = parsed;

  if (!existsSync(projectPath)) throw new UsageError(`Path does not exist: ${projectPath}`);

  console.log(`🔍 Bugoslav Scannerov v${VERSION}`);
  console.log(`📁 Scanning project: ${projectPath}`);
  if (config.skipPackages.length > 0) console.log(`⏭️  Skipping packages: ${config.skipPackages.join(", ")}`);
  console.log("");

  const dependencies = detectAndParse(projectPath, config.scanType);
  if (dependencies.length === 0) {
    throw new UsageError("No dependencies found. Make sure package.json or .csproj files exist.");
  }
  console.log(`📦 Found ${dependencies.length} dependencies to scan\n`);

  console.log("🔎 Scanning with OSV...");
  const found = await scanWithOSV(dependencies);
  console.log(`✓ OSV scan complete: ${found.length} advisories matched\n`);

  const unique = deduplicateResults(found);
  if (config.enrich) {
    console.log("🔎 Enriching with CISA KEV and EPSS...");
    await enrichResults(unique);
  }
  const results = deduplicateResults(filterSkippedPackages(unique, config.skipPackages));
  const skipped = unique.length - results.length;
  if (skipped > 0) console.log(`⏭️  Skipped ${skipped} vulnerabilities due to skipped packages`);

  let fixSuggestions: FixSuggestion[] | undefined;
  if (config.suggestFixes && results.length > 0) {
    console.log("🔧 Analyzing fixes...\n");
    fixSuggestions = await suggestFixes(results);
    console.log(`✓ Found ${fixSuggestions.length} fix suggestions\n`);
  }

  const reportPath = await generateReport(results, config, unique, fixSuggestions);
  printSummary(results, reportPath, fixSuggestions);

  if (shouldFail(results, config.failOn)) {
    console.log(`\n❌ Vulnerabilities at or above "${config.failOn}" severity found`);
    return 1;
  }
  console.log(results.length > 0 ? `\n✅ No vulnerabilities at or above "${config.failOn}" severity` : "\n✅ No vulnerabilities found");
  return 0;
}

function detectAndParse(projectPath: string, scanType: Config["scanType"]): Dependency[] {
  const dependencies: Dependency[] = [];

  if (existsSync(join(projectPath, "package.json"))) {
    console.log("📦 Detected npm project");
    dependencies.push(...parseNpmDependencies(projectPath, scanType));
  }

  for (const csproj of findCsprojFiles(projectPath)) {
    console.log(`📦 Detected .NET project: ${csproj}`);
    dependencies.push(...parseDotNetDependencies(csproj, scanType));
  }

  return dedupeDependencies(dependencies);
}

function printSummary(
  results: ReturnType<typeof deduplicateResults>,
  reportPath: string,
  fixSuggestions?: FixSuggestion[]
) {
  const stats = calculateStats(results);
  const exploited = results.filter(r => r.knownExploited).length;

  console.log("=".repeat(60));
  console.log("📊 SCAN SUMMARY");
  console.log("=".repeat(60));
  console.log(`Total vulnerabilities: ${results.length}`);
  console.log(`  Critical: ${stats.critical}`);
  console.log(`  High: ${stats.high}`);
  console.log(`  Medium: ${stats.medium}`);
  console.log(`  Low: ${stats.low}`);
  if (stats.unknown > 0) console.log(`  Unknown: ${stats.unknown}`);
  if (exploited > 0) console.log(`  🔥 Known exploited (CISA KEV): ${exploited}`);
  console.log(`\n📄 Report generated: ${reportPath}`);

  const fixable = fixSuggestions?.filter(f => f.fixAvailable) ?? [];
  if (fixable.length === 0) return;

  console.log("\n" + "=".repeat(60));
  console.log("🔧 FIX SUGGESTIONS");
  console.log("=".repeat(60));
  console.log(`${fixable.length} of ${fixSuggestions!.length} vulnerable packages can be fixed\n`);
  for (const [label, ecosystem] of [["📦 NPM Packages:", "npm"], ["📦 .NET Packages:", "nuget"]] as const) {
    const fixes = fixable.filter(f => f.ecosystem === ecosystem);
    if (fixes.length === 0) continue;
    console.log(label);
    for (const fix of fixes.slice(0, 5)) {
      console.log(`  ${fix.package} ${fix.currentVersion} → ${fix.recommendedVersion}`);
      console.log(`    ${fix.command}`);
    }
    if (fixes.length > 5) console.log(`  ... and ${fixes.length - 5} more (see report)`);
    console.log("");
  }
}

function printHelp() {
  console.log(`
Bugoslav Scannerov v${VERSION}

Usage: bun run scan [options]

Options:
  -p, --path <path>        Project path to scan (default: current directory)
  -t, --scanType <type>    all | fast. all scans transitive dependencies too, fast only direct ones (default: all)
  -o, --output <path>      Report path without extension (default: bugoslav-scannerov-report)
  -f, --format <format>    markdown | json | html (default: html)
      --skip <packages>    Comma-separated package names to skip
      --suggestFixes       Suggest fixes for vulnerabilities
      --failOn <severity>  Exit with code 1 at or above: none | low | medium | high | critical (default: low)
      --noEnrich           Do not query CISA KEV and EPSS
  -h, --help               Show this help message

Exit codes: 0 = pass, 1 = vulnerabilities at or above --failOn, 2 = error.

Examples:
  bun run scan
  bun run scan --path ./my-project --scanType fast --failOn high
  bun run scan --format json --output report
  `);
}

main()
  .then(code => process.exit(code))
  .catch(error => {
    console.error(`\n❌ ${error instanceof UsageError ? error.message : `Scan failed: ${error instanceof Error ? error.message : error}`}`);
    process.exit(2);
  });
