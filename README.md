# 🔒 Bugoslav Scannerov

CLI tool for scanning vulnerabilities in **JavaScript/TypeScript, .NET, Python, Go and Rust** projects. Detection is powered by [OSV.dev](https://osv.dev/), which aggregates the GitHub Advisory Database and ecosystem-specific advisory databases. Findings are enriched with exploitation data from **CISA KEV** and **EPSS**.

## ✨ Features

- 🔍 Five ecosystems in one scan, see [Supported ecosystems](#-supported-ecosystems)
- ⚡ Fast: one batched OSV query, no API keys or tokens needed
- 🎯 Accurate: severity from the CVSS vector, the fix version taken from the advisory range that matches your installed version, withdrawn advisories ignored
- 🔥 Prioritisation: flags vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog and shows the EPSS exploit probability
- 📄 Reports: **Markdown**, **JSON**, **HTML**, **SARIF** (GitHub Code Scanning) and a **CycloneDX 1.5 SBOM**
- 🙈 Accepted risks: ignore rules with a mandatory reason and optional expiry date
- 🚦 CI-ready: configurable failure threshold (`--failOn`) and meaningful exit codes
- 🔧 Optional fix suggestions with ready-to-run update commands

## 🚀 Installation

Requires Node.js 20+ (or [Bun](https://bun.sh/)).

```bash
# Run without installing
npx bugoslav-scannerov --path ./my-project

# Or install globally; the command is `bugoslav`
npm install -g bugoslav-scannerov
```

From source (needs [Bun](https://bun.sh/)):

```bash
git clone https://github.com/BElluu/BugoslavScannerov.git
cd BugoslavScannerov
bun install
bun run scan --path ./my-project
```

## 📖 Usage

```bash
# Scan the current directory, write bugoslav-scannerov-report.html
bugoslav

# Another project, JSON report, fail the build only on high/critical findings
bugoslav --path ./my-project --format json --output security-report --failOn high

# Direct dependencies only, with fix suggestions
bugoslav --scanType fast --suggestFixes
```

## 🌍 Supported ecosystems

| Ecosystem | Files read | Transitive dependencies |
|-----------|-----------|-------------------------|
| **npm** (JS/TS) | `package.json`, `package-lock.json` (v1, v2, v3) | via `package-lock.json` |
| **NuGet** (.NET) | `*.csproj`, `packages.lock.json`, `Directory.Packages.props` | via `packages.lock.json` |
| **PyPI** (Python) | `requirements*.txt` (exact `==` pins), `poetry.lock`, `uv.lock`, `Pipfile.lock` | lockfiles |
| **Go** | `go.mod` | all `require` entries; `// indirect` ones are skipped with `--scanType fast` |
| **crates.io** (Rust) | `Cargo.lock` | lockfile |

Manifests are searched recursively (except in `node_modules`, `bin`, `obj`, `.git`, virtual environments, `target` and `vendor`), except npm, which reads the project root only. Lockfiles for Python and Rust do not mark direct dependencies, so `--scanType` does not apply to them.

Adding an ecosystem is one file in `src/ecosystems/` plus one line in `src/ecosystems/index.ts`: OSV already covers Maven, RubyGems, Packagist and more.

## 🔧 CLI Options

| Option | Shortcut | Description | Default |
|--------|----------|-------------|---------|
| `--path` | `-p` | Project path to scan | `.` |
| `--scanType` | `-t` | `all` (including transitive dependencies) or `fast` (direct only) | `all` |
| `--output` | `-o` | Report path **without extension**; the format's extension is added | `bugoslav-scannerov-report` |
| `--format` | `-f` | `markdown`, `json`, `html`, `sarif` or `cyclonedx` | `html` |
| `--skip` | | Comma-separated package names to skip (case-insensitive) | none |
| `--suggestFixes` | | Suggest fixes using the package registries | `false` |
| `--failOn` | | Exit with code 1 at or above this severity: `none`, `low`, `medium`, `high`, `critical` | `low` |
| `--noEnrich` | | Do not query CISA KEV and EPSS | `false` |
| `--config` | | Config file with ignore rules | `.bugoslavrc.json` in the project |
| `--help` | `-h` | Show help | |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities at or above `--failOn` |
| `1` | At least one vulnerability at or above `--failOn` |
| `2` | The scan could not complete (invalid arguments, network failure, unreadable files) |

A scan that cannot reach OSV fails with code `2` rather than reporting a clean result. Vulnerabilities with unknown severity are treated as `medium` for `--failOn`.

### Scan type: `all` vs `fast`

- **`all`**: every dependency, including transitive ones. This needs a lockfile: `package-lock.json` for npm, `packages.lock.json` for .NET (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`). Without one only direct dependencies are scanned and a warning is shown.
- **`fast`**: direct dependencies only. With a lockfile the exact installed versions are used; without one, version ranges in `package.json` are resolved to their lower bound.

### Fix suggestions (`--suggestFixes`)

Finds the lowest published version that fixes all advisories of a package, builds the update command (for example `npm install pkg@x`, `dotnet add package pkg --version x`, `go get pkg@vx`) and flags major-version jumps as breaking. If no advisory lists a fix, the latest stable release is suggested and marked as unverified.

### Skipping packages (`--skip`)

Excludes the named packages from the results. Skipped findings are listed separately in the report. This hides every present and future advisory of the package, so prefer an ignore rule for accepted risks.

### Ignoring accepted risks (`.bugoslavrc.json`)

To accept a specific advisory, add a rule to `.bugoslavrc.json` in the scanned project (or pass `--config <path>`):

```json
{
  "ignore": [
    {
      "id": "CVE-2021-23337",
      "package": "lodash",
      "reason": "Template option is never built from user input",
      "expires": "2027-01-31"
    }
  ]
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | CVE or GHSA id of the advisory |
| `reason` | yes | Why the risk is accepted, so exceptions stay reviewable |
| `package` | no | Limit the rule to one package |
| `expires` | no | Last day (`YYYY-MM-DD`, inclusive) the rule applies. Afterwards the finding is reported again and a warning is printed |

Ignored findings are listed in a separate section of the report and do not affect `--failOn`.

## 🛡️ GitHub Code Scanning (SARIF)

`--format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) file. Each finding points at the manifest or lockfile that declares the dependency, and the CVSS score is passed as `security-severity` so GitHub shows the right severity.

```yaml
# .github/workflows/security.yml
name: Dependency scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx bugoslav-scannerov --format sarif --output results --failOn none
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

`--failOn none` lets the upload step decide; use a different threshold if the job itself should fail.

## 📋 SBOM (CycloneDX)

`--format cyclonedx` writes a [CycloneDX 1.5](https://cyclonedx.org/) JSON bill of materials to `<output>.cdx.json`:

```bash
bugoslav --format cyclonedx --output sbom
```

- **Components:** every scanned dependency, vulnerable or not, identified by [package URL](https://github.com/package-url/purl-spec) and with the manifest that declares it (`evidence.occurrences`).
- **Vulnerabilities:** one entry per advisory with severity, CVSS score, recommended upgrade and the components it affects. CISA KEV and EPSS appear as properties. Ignored findings are left out.
- The component list reflects what was scanned: with `--scanType fast`, or without lockfiles, transitive dependencies are not included.
- The dependency graph (`dependencies`) is not emitted, because the scanner does not track which package requires which.

## 📊 Data sources

| Source | Used for | Notes |
|--------|----------|-------|
| [OSV.dev](https://osv.dev/) | Vulnerability detection | No key, batched queries |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited flag | Needs a CVE id |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability | Needs a CVE id |
| npm, NuGet, PyPI, Go proxy, crates.io | Fix suggestions | Only with `--suggestFixes` |

KEV and EPSS are advisory: if they are unavailable the scan continues without them.

## 🗂️ Project structure

```
src/
├── index.ts          # CLI entry point
├── types.ts          # Shared types
├── ecosystems/       # One file per ecosystem: manifest parsing, OSV name, package registry
├── files.ts          # Recursive file search, TOML lockfile reader
├── osv.ts            # OSV client and advisory conversion
├── enrich.ts         # CISA KEV and EPSS
├── config.ts         # .bugoslavrc.json ignore rules
├── sarif.ts          # SARIF 2.1.0 output
├── cyclonedx.ts      # CycloneDX 1.5 SBOM
├── version.ts        # Version comparison and OSV range matching
├── cvss.ts           # CVSS v3 base score
├── results.ts        # Deduplication, sorting, fail threshold
├── fix-suggester.ts  # Fix suggestions
├── reporter.ts       # Markdown / JSON / HTML / SARIF / CycloneDX output
└── utils.ts
test/                 # bun test
```

## 🧪 Development

```bash
bun test
bun run typecheck
bun run build   # bundles to dist/ for Node
```

## 📄 License

[MIT](LICENSE)
