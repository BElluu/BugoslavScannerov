# 🔒 Bugoslav Scannerov

CLI tool for scanning vulnerabilities in **.NET** and **TypeScript/JavaScript** projects. Detection is powered by [OSV.dev](https://osv.dev/), which aggregates the GitHub Advisory Database and ecosystem-specific advisory databases. Findings are enriched with exploitation data from **CISA KEV** and **EPSS**.

## ✨ Features

- 🔍 **npm** projects: `package.json`, `package-lock.json` (v1, v2, v3)
- 🔍 **.NET** projects: `*.csproj`, `packages.lock.json`, central package management (`Directory.Packages.props`)
- ⚡ Fast: one batched OSV query, no API keys or tokens needed
- 🎯 Accurate: severity from the CVSS vector, the fix version taken from the advisory range that matches your installed version, withdrawn advisories ignored
- 🔥 Prioritisation: flags vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog and shows the EPSS exploit probability
- 📄 Reports: **Markdown**, **JSON**, **HTML**
- 🚦 CI-ready: configurable failure threshold (`--failOn`) and meaningful exit codes
- 🔧 Optional fix suggestions with ready-to-run update commands

## 🚀 Installation

Requires [Bun](https://bun.sh/).

```bash
git clone https://github.com/BElluu/BugoslavScannerov.git
cd BugoslavScannerov
bun install
```

## 📖 Usage

```bash
# Scan the current directory, write bugoslav-scannerov-report.html
bun run scan

# Scan another project, JSON report, fail the build only on high/critical findings
bun run scan --path ./my-project --format json --output security-report --failOn high

# Direct dependencies only, with fix suggestions
bun run scan --scanType fast --suggestFixes
```

## 🔧 CLI Options

| Option | Shortcut | Description | Default |
|--------|----------|-------------|---------|
| `--path` | `-p` | Project path to scan | `.` |
| `--scanType` | `-t` | `all` (including transitive dependencies) or `fast` (direct only) | `all` |
| `--output` | `-o` | Report path **without extension**; the format's extension is added | `bugoslav-scannerov-report` |
| `--format` | `-f` | `markdown`, `json` or `html` | `html` |
| `--skip` | | Comma-separated package names to skip (case-insensitive) | none |
| `--suggestFixes` | | Suggest fixes using the npm and NuGet registries | `false` |
| `--failOn` | | Exit with code 1 at or above this severity: `none`, `low`, `medium`, `high`, `critical` | `low` |
| `--noEnrich` | | Do not query CISA KEV and EPSS | `false` |
| `--help` | `-h` | Show help | |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities at or above `--failOn` |
| `1` | At least one vulnerability at or above `--failOn` |
| `2` | The scan could not complete (invalid arguments, network failure, unreadable files) |

A scan that cannot reach OSV fails with code `2` rather than reporting a clean result. Vulnerabilities with unknown severity are treated as `medium` for `--failOn`.

### Scan type: `all` vs `fast`

- **`all`**: every dependency, including transitive ones. For npm this needs `package-lock.json`, for .NET `packages.lock.json` (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`). Without a lockfile only direct dependencies are scanned and a warning is shown.
- **`fast`**: direct dependencies only. With a lockfile the exact installed versions are used; without one, version ranges in `package.json` are resolved to their lower bound.

### Fix suggestions (`--suggestFixes`)

Finds the lowest published version that fixes all advisories of a package, builds the update command (`npm install pkg@x` / `dotnet add package pkg --version x`) and flags major-version jumps as breaking. If no advisory lists a fix, the latest stable release is suggested and marked as unverified.

### Skipping packages (`--skip`)

Excludes the named packages from the results. Skipped findings are listed separately in the report.

## 📊 Data sources

| Source | Used for | Notes |
|--------|----------|-------|
| [OSV.dev](https://osv.dev/) | Vulnerability detection | No key, batched queries |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited flag | Needs a CVE id |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability | Needs a CVE id |
| npm registry, NuGet | Fix suggestions | Only with `--suggestFixes` |

KEV and EPSS are advisory: if they are unavailable the scan continues without them.

## 🗂️ Project structure

```
src/
├── index.ts          # CLI entry point
├── types.ts          # Shared types
├── parsers.ts        # package.json / package-lock.json / .csproj parsers
├── osv.ts            # OSV client and advisory conversion
├── enrich.ts         # CISA KEV and EPSS
├── version.ts        # Version comparison and OSV range matching
├── cvss.ts           # CVSS v3 base score
├── results.ts        # Deduplication, sorting, fail threshold
├── fix-suggester.ts  # Fix suggestions
├── reporter.ts       # Markdown / JSON / HTML reports
└── utils.ts
test/                 # bun test
```

## 🧪 Development

```bash
bun test
bun run typecheck
```

## 📄 License

[MIT](LICENSE)
