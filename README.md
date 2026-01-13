# 🔒 Bugoslav Skannerov

CLI tool for automatic vulnerability scanning in .NET and TypeScript/JavaScript projects using three reliable databases: **OSV**, **GitHub Advisory Database**, and **NVD**.

## ✨ Features

- 🔍 Scanning **npm** projects (package.json, package-lock.json)
- 🔍 Scanning **.NET** projects (*.csproj, packages.lock.json)
- 📊 Integration with three vulnerability databases:
  - **OSV (Open Source Vulnerabilities)** - Google, fast and comprehensive
  - **GitHub Advisory Database** - official advisories from GitHub
  - **NVD (National Vulnerability Database)** - NIST CVE database
- 📄 Three report formats: **Markdown**, **JSON**, **HTML**
- 🚀 Ready for CI/CD use
- ⚡ Fast execution thanks to Bun

## 🚀 Installation

```bash
# Install Bun (if you don't have it)
curl -fsSL https://bun.sh/install | bash

# Clone the repository
git clone git@github.com:BElluu/BugoslavScannerov.git
cd Bugoslav Skanerov

# Install dependencies
bun install
```

## 📖 Usage

### Basic scanning

```bash
# Save report in HTML format
bun run scan --path ./my-project --format html --output security-report --scanType fast
```

```bash
# Use only OSV and GitHub (skip NVD)
bun run scan --sources osv,github
```

### Environment variables

```bash
# GitHub Advisory
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx

# NVD API (increases rate limit)
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## 🔧 CLI Options

| Option | Shortcut | Description | Default |
|--------|----------|-------------|---------|
| `--path` | `-p` | Project path to scan | `.` (current directory) |
| `--scanType` | `-t` | Scan type: `all` or `fast` | `all` |
| `--sources` | `-s` | Data sources | `osv,github,nvd` |
| `--output` | `-o` | Report file path | `bugoslav-scannerov-report` |
| `--format` | `-f` | Report format | `html` |
| `--skip` | | Comma-separated packages to skip | (none) |
| `--suggestFixes` | | Suggest fixes for vulnerabilities | `false` |
| `--help` | `-h` | Show help | |

### Scan Type: `all` vs `fast`

- **`all`** (default): Scans all dependencies including transitive (nested) dependencies. For npm projects, it uses `package-lock.json` which contains the complete dependency tree. This provides comprehensive coverage but takes longer to scan.
- **`fast`**: Scans only direct dependencies (those listed in `package.json` or `.csproj` files). For npm projects, it only reads `package.json` without analyzing nested dependencies. This is faster but may miss vulnerabilities in transitive dependencies.

### Suggest Fixes (`--suggestFixes`)

When enabled, the tool analyzes found vulnerabilities and suggests specific fixes:

- **Checks available versions** in package registries (npm/NuGet)
- **Generates update commands** ready to run (e.g., `npm install package@version` or `dotnet add package package --version version`)
- **Identifies breaking changes** - warns if the recommended update involves a major version change
- **Provides recommended versions** based on fixed versions from vulnerability databases or latest compatible versions
- **Includes fix suggestions in reports** with detailed information about each fixable vulnerability

# The report will include a "Fix Suggestions" section with commands to update vulnerable packages

### Skip Packages (`--skip`)

Allows you to exclude specific packages from vulnerability scanning. Vulnerabilities related to skipped packages will be filtered out from the results.

- **Comma-separated list** of package names to skip
- **Case-insensitive** matching
- **Useful for** packages that you know are false positives, or packages you cannot update due to compatibility constraints

**Example:**
```bash
# Skip specific packages during scan
bun run scan --skip package1,package2,package3
```

## 📊 Report Formats

### Markdown (.md)
Readable format for documentation and pull requests:
```bash
bun run scan --format markdown
```

### JSON (.json)
Ideal for further automation and parsing:
```bash
bun run scan --format json
```

### HTML (.html)
Visual report with coloring and statistics:
```bash
bun run scan --format html
```

## 🗂️ Project Structure

```
vuln-scanner-cli/
├── src/
│   ├── index.ts          # Main CLI file
│   ├── types.ts          # TypeScript interfaces
│   ├── parsers.ts        # package.json and .csproj parsers
│   ├── scanners.ts       # OSV, GitHub, NVD integrations
│   └── reporter.ts       # Report generators
├── package.json
├── tsconfig.json
└── README.md
```

## 📝 Example Output

```
🔍 Bugoslav Scannerov v1.0.0
📁 Scanning project: ./my-project
🎯 Sources: osv, github, nvd

📦 Detected npm project
📦 Found 245 dependencies to scan

🔎 Scanning with OSV...
✓ OSV scan complete: 3 vulnerabilities found

🔎 Scanning with GitHub Advisory...
✓ GitHub scan complete: 2 vulnerabilities found

============================================================
📊 SCAN SUMMARY
============================================================
Total vulnerabilities: 3
  Critical: 1
  High: 1
  Medium: 1
  Low: 0

📄 Report generated: bugoslav-scannerov-report.md

❌ Build failed due to vulnerabilities matching fail criteria
```

## 🔒 Vulnerability Database Information

### OSV (Open Source Vulnerabilities)
- **Source**: Google
- **Rate limit**: None
- **Documentation**: https://osv.dev/

### GitHub Advisory Database
- **Source**: GitHub
- **Rate limit**: 5000 req/hour (with token)
- **Documentation**: https://docs.github.com/en/graphql/overview/about-the-graphql-api

### NVD (National Vulnerability Database)
- **Source**: NIST
- **Rate limit**: 5 req/30s (without key), 50 req/30s (with key)
- **Documentation**: https://nvd.nist.gov/developers
