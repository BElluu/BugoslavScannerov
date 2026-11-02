import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Config, FixSuggestion, ScanResult } from './types.js';
import { escapeHtml, safeUrl } from './utils.js';
import { ECOSYSTEMS } from './ecosystems/index.js';
import { toSarif } from './sarif.js';
import pkg from '../package.json' with { type: 'json' };

export async function generateReport(
  results: ScanResult[],
  config: Config,
  allResults?: ScanResult[],
  fixSuggestions?: FixSuggestion[]
): Promise<string> {
  const timestamp = new Date().toISOString();

  switch (config.outputFormat) {
    case 'json':
      return generateJSON(results, config, allResults, fixSuggestions, timestamp);
    case 'sarif':
      return writeReport(config, 'sarif', JSON.stringify(toSarif(results, pkg.version), null, 2));
    case 'markdown':
      return generateMarkdown(results, config, allResults, fixSuggestions, timestamp);
    case 'html':
    default:
      return generateHTML(results, config, allResults, fixSuggestions, timestamp);
  }
}

/** Writes the report to `<outputPath>.<ext>`, creating parent folders. Returns the written path. */
function writeReport(config: Config, extension: string, content: string): string {
  const suffix = `.${extension}`;
  const filename = config.outputPath.toLowerCase().endsWith(suffix) ? config.outputPath : config.outputPath + suffix;
  mkdirSync(dirname(filename), { recursive: true });
  writeFileSync(filename, content);
  return filename;
}

function safeLink(url: string | null): string | null {
  return url && safeUrl(url) ? url : null;
}

function generateJSON(
  results: ScanResult[],
  config: Config,
  allResults: ScanResult[] | undefined,
  fixSuggestions: FixSuggestion[] | undefined,
  timestamp: string
): string {
  const skippedResults = allResults
    ? allResults.filter(r => !results.includes(r))
    : [];
  const report = {
    timestamp,
    summary: {
      total: results.length || 0,
      critical: results.filter(result => result.severity === 'critical').length || 0,
      high: results.filter(result => result.severity === 'high').length || 0,
      medium: results.filter(result => result.severity === 'medium').length || 0,
      low: results.filter(result => result.severity === 'low').length || 0,
      skipped: skippedResults.length || 0,
      fixable: fixSuggestions?.filter(f => f.fixAvailable).length || 0,
      unknown: results.filter(result => result.severity === 'unknown').length || 0,
    },
    config: {
      skipPackages: config.skipPackages,
      suggestFixes: config.suggestFixes,
    },
    vulnerabilities: results,
    skippedVulnerabilities: skippedResults.length > 0 ? skippedResults : undefined,
    fixSuggestions: fixSuggestions || undefined,
  };
  return writeReport(config, 'json', JSON.stringify(report, null, 2));
}

function generateMarkdown(results: ScanResult[], config: Config, allResults: ScanResult[] | undefined, fixSuggestions: FixSuggestion[] | undefined, timestamp: string): string {
  let md = `# Bugoslav Scannerov Report\n\n`;
  md += `**Generated:** ${timestamp}\n\n`;

  const stats = {
    critical: results.filter(r => r.severity === "critical").length || 0,
    high: results.filter(r => r.severity === "high").length || 0,
    medium: results.filter(r => r.severity === "medium").length || 0,
    low: results.filter(r => r.severity === "low").length || 0,
  };

  const skippedResults = allResults
    ? allResults.filter(r => !results.includes(r))
    : [];

  md += `## Summary\n\n`;
  md += `- **Total Vulnerabilities:** ${results.length}\n`;

  if (skippedResults.length > 0) {
    md += `- **Ignored Vulnerabilities:** ${skippedResults.length}\n`;
  }

  if (fixSuggestions) {
    const fixableCount = fixSuggestions.filter(f => f.fixAvailable).length;
    md += `- 🔧 **Fixable:** ${fixableCount} of ${results.length}\n`;
  }

  md += `- 🔴 **Critical:** ${stats.critical}\n`;
  md += `- 🟠 **High:** ${stats.high}\n`;
  md += `- 🟡 **Medium:** ${stats.medium}\n`;
  md += `- 🟢 **Low:** ${stats.low}\n\n`;

  if (config.skipPackages.length > 0) {
    md += `### Ignored Packages\n\n`;
    md += `The following packages were skipped from this report:\n`;
    config.skipPackages.forEach(pkg => {
      md += `- \`${pkg}\`\n`;
    });
    md += `\n`;
  }

  if (fixSuggestions && fixSuggestions.length > 0) {
    md += `## 🔧 Fix Suggestions\n\n`;

    const fixable = fixSuggestions.filter(f => f.fixAvailable);
    const notFixable = fixSuggestions.filter(f => !f.fixAvailable);

    if (fixable.length > 0) {
      md += `### ✅ Fixable (${fixable.length})\n\n`;

      for (const { id, label } of ECOSYSTEMS) {
        const fixes = fixable.filter(f => f.ecosystem === id);
        if (fixes.length === 0) continue;

        md += `#### 📦 ${label}\n\n`;
        md += "```bash\n";
        md += "# Update commands:\n";
        fixes.forEach(fix => {
          md += `${fix.command}\n`;
        });
        md += "```\n\n";

        md += "| Package | Current | Recommended | CVEs Fixed | Notes |\n";
        md += "|---------|---------|-------------|------------|-------|\n";
        fixes.forEach(fix => {
          md += `| \`${fix.package}\` | ${fix.currentVersion} | ${fix.recommendedVersion} | ${fix.vulnerabilityCount} | ${fix.reason || ''} |\n`;
        });
        md += "\n";
      }
    }

    if (notFixable.length > 0) {
      md += `### ⚠️ No Fix Available (${notFixable.length})\n\n`;
      md += "| Package | Current Version | Reason |\n";
      md += "|---------|-----------------|--------|\n";
      notFixable.forEach(fix => {
        md += `| \`${fix.package}\` | ${fix.currentVersion} | ${fix.reason || 'Unknown'} |\n`;
      });
      md += "\n";
      md += "💡 **Recommendations:**\n";
      md += "- Check for alternative packages\n";
      md += "- Monitor package repository for updates\n";
      md += "- Consider implementing workarounds\n";
      md += "- Use `--skip` flag if risk is accepted\n\n";
    }
  }

  md += `## Vulnerabilities\n\n`;

  for (const result of results) {
    const nvdLink = safeLink(generateNVDLink(result.cveId, result.references));
    const ghsaLink = safeLink(generateGHSALink(result.cveId, result.references, result.ghsaId));
    const icon = getSeverityIcon(result.severity);
    md += `### ${icon} ${result.cveId}\n\n`;

    if (nvdLink || ghsaLink) {
      md += `**External Links:** `;
      if (nvdLink) {
        md += `[NVD](${nvdLink})`;
        if (ghsaLink) {
          md += ` | `;
        }
      }
      if (ghsaLink) {
        md += `[GitHub Advisory](${ghsaLink})`;
      }
      md += `\n\n`;
    }
    md += `- **Package:** \`${result.package}@${result.version}\` (${result.ecosystem})\n`;
    md += `- **Severity:** ${result.severity.toUpperCase()}\n`;
    if (result.cvssScore) {
      md += `- **CVSS Score:** ${result.cvssScore}\n`;
    }
    if (result.knownExploited) {
      md += `- 🔥 **Known exploited** (CISA KEV)\n`;
    }
    if (result.epss !== undefined) {
      md += `- **EPSS:** ${(result.epss * 100).toFixed(1)}%\n`;
    }
    if (result.fixedVersion) {
      md += `- **Fixed in:** ${result.fixedVersion}\n`;
    }

    const fix = fixSuggestions?.find(f => f.package === result.package && f.currentVersion === result.version);
    if (fix?.fixAvailable) {
      md += `- 🔧 **Fix Available:** Update to ${fix.recommendedVersion}\n`;
    }

    md += `\n**Description:**\n${result.summary}\n\n`;

    if (result.details) {
      md += `**Details:**\n${result.details.substring(0, 300)}${result.details.length > 300 ? "..." : ""}\n\n`;
    }

    if (result.references.length > 0) {
      md += `**References:**\n`;
      result.references.slice(0, 3).forEach(ref => {
        md += `- ${ref}\n`;
      });
      md += `\n`;
    }

    md += `---\n\n`;
  }

  if (skippedResults.length > 0) {
    md += `## Ignored Vulnerabilities\n\n`;
    md += `The following vulnerabilities were found but ignored (skipped packages or ignore rules):\n\n`;

    const groupedByPackage = skippedResults.reduce((acc, vuln) => {
      if (!acc[vuln.package]) acc[vuln.package] = [];
      acc[vuln.package].push(vuln);
      return acc;
    }, {} as Record<string, ScanResult[]>);

    for (const [pkg, vulns] of Object.entries(groupedByPackage)) {
      md += `### \`${pkg}\` - ${vulns.length} vulnerabilities ignored\n\n`;
      vulns.forEach(v => {
        md += `- ${getSeverityIcon(v.severity)} **${v.cveId}** (${v.severity}): ${v.summary.substring(0, 100)}...\n`;
      });
      md += `\n`;
    }
  }

  return writeReport(config, 'md', md);
}

function generateHTML(results: ScanResult[], config: Config, allResults: ScanResult[] | undefined, fixSuggestions: FixSuggestion[] | undefined, timestamp: string): string {
  const stats = {
    critical: results.filter(r => r.severity === "critical").length || 0,
    high: results.filter(r => r.severity === "high").length || 0,
    medium: results.filter(r => r.severity === "medium").length || 0,
    low: results.filter(r => r.severity === "low").length || 0,
  };

  const skippedResults = allResults
    ? allResults.filter(r => !results.includes(r))
    : [];

  const fixableCount = fixSuggestions?.filter(f => f.fixAvailable).length || 0;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bugoslav Skannerov Report</title>
    <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    html {
      scroll-behavior: smooth;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #e3f2fd 0%, #eef1f5 100%);
      padding: 40px 0;
      line-height: 1.6;
      color: #333;
    }
    .container {
      width: 95%;
      max-width: 1100px;
      margin: 0 auto;
      background: white;
      padding: 40px 50px;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    }
    h1 {
      color: #1a237e;
      font-size: 32px;
      margin-bottom: 12px;
      text-align: center;
      font-weight: 700;
      letter-spacing: -0.5px;
    }
    .timestamp {
      color: #888;
      font-size: 13px;
      margin-bottom: 40px;
      text-align: center;
      font-weight: 500;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 16px;
      margin: 0 auto 40px;
      max-width: 950px;
    }
    .stat-card {
      padding: 24px 16px;
      border-radius: 10px;
      text-align: center;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      font-weight: 600;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .stat-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.12);
    }
    .stat-card h3 {
      font-size: 36px;
      margin-bottom: 8px;
      font-weight: 700;
    }
    .stat-card p {
      font-size: 13px;
      color: #555;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

.critical { background: #fdecea; color: #b71c1c; }
.high { background: #fff3e0; color: #e65100; }
.medium { background: #fff8e1; color: #f57c00; }
.low { background: #e8f5e9; color: #2e7d32; }
.skipped { background: #eceff1; color: #455a64; }
    .ignored-packages {
      background: linear-gradient(135deg, #f5f5f5 0%, #eeeeee 100%);
      border-left: 4px solid #757575;
      padding: 20px;
      margin: 0 auto 30px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
      max-width: 950px;
    }
    .ignored-packages h3 {
      font-size: 16px;
      margin-bottom: 14px;
      color: #424242;
      font-weight: 600;
    }
    .ignored-packages ul {
      list-style: none;
      padding-left: 0;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .ignored-packages li {
      display: inline-block;
      background: white;
      border: 1px solid #bdbdbd;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 13px;
      font-family: 'Courier New', Consolas, monospace;
      color: #424242;
      font-weight: 500;
      transition: all 0.2s;
    }
    .ignored-packages li:hover {
      background: #e0e0e0;
      border-color: #757575;
    }
    .meta {
      display: flex;
      gap: 16px;
      margin-bottom: 16px;
      font-size: 13px;
      color: #666;
      flex-wrap: wrap;
    }
    .meta span {
      display: flex;
      align-items: center;
      gap: 6px;
      background: #fff;
      padding: 6px 12px;
      border-radius: 4px;
      border: 1px solid #e0e0e0;
    }
    .meta code {
      background: #f5f5f5;
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 12px;
    }
    .summary-text {
      margin: 16px 0;
      line-height: 1.6;
      color: #333;
      background: #fff;
      padding: 14px;
      border-radius: 6px;
      border-left: 3px solid #1976d2;
    }
    .references {
      margin-top: 16px;
      background: #fff;
      padding: 12px;
      border-radius: 6px;
    }
    .references strong {
      color: #555;
      font-size: 13px;
    }
    .references a {
      color: #1976d2;
      text-decoration: none;
      font-size: 12px;
      display: block;
      margin-top: 6px;
      word-break: break-all;
    }
    .references a:hover {
      text-decoration: underline;
      color: #1565c0;
    }
    .no-vulns {
      text-align: center;
      padding: 60px;
      color: #2e7d32;
      font-size: 24px;
    }
    .skipped-section {
  background: linear-gradient(135deg, #f5f5f5 0%, #eeeeee 100%);
  padding: 32px;
  border-radius: 10px;
  margin: 40px auto 0;
  border: 1px solid #ddd;
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
  max-width: 950px;
}
.skipped-section h2 {
  color: #424242;
  margin-bottom: 20px;
  font-size: 22px;
  font-weight: 600;
}
    .skipped-package {
      background: white;
      border-left: 4px solid #757575;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 6px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    }
    .skipped-package h3 {
      font-size: 16px;
      margin-bottom: 14px;
      color: #424242;
      font-weight: 600;
    }
    .skipped-package code {
      background: #e0e0e0;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 14px;
    }
    .skipped-vuln {
      border-bottom: 1px solid #f0f0f0;
      padding: 10px 0;
      font-size: 13px;
      line-height: 1.6;
    }
    .skipped-vuln:last-child { border-bottom: none; }

    .section {
  margin-top: 50px;
  padding-top: 10px;
  border-top: 2px solid #eee;
}

.fix-section {
  background: linear-gradient(135deg, #f4f9ff 0%, #e8f4ff 100%);
  border-left: 5px solid #1976d2;
  padding: 32px;
  margin: 40px auto 30px;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(25, 118, 210, 0.1);
  max-width: 950px;
}
.fix-section h2 {
  color: #1565c0;
  margin-bottom: 20px;
  font-size: 22px;
}
.fix-section h3 {
  color: #1976d2;
  margin-top: 24px;
  margin-bottom: 12px;
  font-size: 18px;
}
.fix-commands {
  background: #1e1e1e;
  color: #4ec9b0;
  padding: 20px;
  border-radius: 8px;
  font-family: 'Courier New', Consolas, monospace;
  margin: 16px 0;
  overflow-x: auto;
  font-size: 13px;
  line-height: 1.8;
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
}
    .fix-table {
  width: 100%;
  border-collapse: collapse;
  margin: 20px 0;
  font-size: 13px;
  background: white;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}
.fix-table th {
  background: linear-gradient(180deg, #1976d2 0%, #1565c0 100%);
  color: white;
  padding: 14px 12px;
  text-align: left;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.5px;
}
.fix-table td {
  padding: 14px 12px;
  border-bottom: 1px solid #f0f0f0;
}
.fix-table tr:hover td {
  background: #f8f9fa;
}
.fix-table tr:last-child td { border-bottom: none; }
.fix-table code {
  background: #f5f5f5;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  color: #d32f2f;
  font-weight: 500;
}
    .fix-badge {
      display: inline-block;
      padding: 5px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .fix-badge.safe {
      background: #c8e6c9;
      color: #2e7d32;
      border: 1px solid #81c784;
    }
    .fix-badge.breaking {
      background: #ffccbc;
      color: #d84315;
      border: 1px solid #ff8a65;
    }
    .no-fix-section {
      background: linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%);
      border-left: 5px solid #ff9800;
      padding: 24px;
      margin: 24px 0;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(255, 152, 0, 0.1);
    }
    .no-fix-section h3 {
      color: #e65100;
      margin-bottom: 16px;
    }
    .no-fix-section ul {
      margin-top: 12px;
      padding-left: 24px;
    }
    .no-fix-section li {
      margin: 8px 0;
      color: #555;
    }
    .external-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      border-radius: 6px;
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .nvd-link {
      background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
      color: white;
    }
    .nvd-link:hover {
      background: linear-gradient(135deg, #1e40af 0%, #2563eb 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(30, 58, 138, 0.3);
    }
    .github-link {
      background: linear-gradient(135deg, #24292e 0%, #1a1e22 100%);
      color: white;
    }
    .github-link:hover {
      background: linear-gradient(135deg, #0366d6 0%, #005cc5 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(3, 102, 214, 0.3);
    }
    .external-link:active {
      transform: translateY(0);
    }

    .vulnerability {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 24px;
  margin: 0 auto 25px;
  background: #fafafa;
  transition: box-shadow 0.2s, transform 0.2s;
  max-width: 950px;
}
.vulnerability:hover {
  box-shadow: 0 4px 12px rgba(0,0,0,0.12);
  transform: translateY(-2px);
}
.vuln-header {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 10px;
}
.vuln-id {
  font-size: 18px;
  font-weight: 700;
  color: #1a237e;
  letter-spacing: 0.3px;
}
.severity-badge {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 11px;
  color: white;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  transition: all 0.2s;
}
.severity-badge:hover {
  transform: scale(1.05);
}
.severity-critical {
  background: linear-gradient(135deg, #c62828 0%, #b71c1c 100%);
  box-shadow: 0 2px 6px rgba(198, 40, 40, 0.4);
}
.severity-high {
  background: linear-gradient(135deg, #ef6c00 0%, #e65100 100%);
  box-shadow: 0 2px 6px rgba(239, 108, 0, 0.4);
}
.severity-medium {
  background: linear-gradient(135deg, #fbc02d 0%, #f9a825 100%);
  color: #212121;
  box-shadow: 0 2px 6px rgba(251, 192, 45, 0.4);
}
.severity-low {
  background: linear-gradient(135deg, #388e3c 0%, #2e7d32 100%);
  box-shadow: 0 2px 6px rgba(56, 142, 60, 0.4);
}

@media (max-width: 768px) {
  .container {
    width: 100%;
    padding: 24px 20px;
    border-radius: 0;
  }
  .summary {
    grid-template-columns: repeat(2, 1fr);
  }
  .stat-card h3 {
    font-size: 28px;
  }
  h1 {
    font-size: 24px;
  }
  .vulnerability {
    padding: 16px;
  }
  .fix-section, .skipped-section {
    padding: 20px;
  }
}

  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 Vulnerability Scan Report</h1>
    <div class="timestamp">Generated: ${timestamp}</div>

    ${config.skipPackages.length > 0 ? `
      <div class="ignored-packages">
        <h3>⏭️ Ignored Packages</h3>
        <ul>
          ${config.skipPackages.map(pkg => `<li>${escapeHtml(pkg)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}

    <div class="summary">
      <div class="stat-card critical">
        <h3>${stats.critical}</h3>
        <p>Critical</p>
      </div>
      <div class="stat-card high">
        <h3>${stats.high}</h3>
        <p>High</p>
      </div>
      <div class="stat-card medium">
        <h3>${stats.medium}</h3>
        <p>Medium</p>
      </div>
      <div class="stat-card low">
        <h3>${stats.low}</h3>
        <p>Low</p>
      </div>
    </div>

    ${skippedResults.length > 0 ? `
        <div class="stat-card skipped">
          <h3>${skippedResults.length}</h3>
          <p>Skipped</p>
        </div>
      ` : ''}
      ${fixableCount > 0 ? `
        <div class="stat-card" style="background: #e8f5e9; color: #2e7d32;">
          <h3>${fixableCount}</h3>
          <p>Fixable</p>
        </div>
      ` : ''}
    </div>
    ${fixSuggestions && fixSuggestions.length > 0 ? generateFixSuggestionsHTML(fixSuggestions) : ''}

    ${results.map(result => {
    const nvdLink = safeLink(generateNVDLink(result.cveId, result.references));
    const ghsaLink = safeLink(generateGHSALink(result.cveId, result.references, result.ghsaId));
    const fix = fixSuggestions?.find(f => f.package === result.package && f.currentVersion === result.version);
    return `
      <div class="vulnerability">
        <div class="vuln-header">
          <div class="vuln-id">${escapeHtml(result.cveId)}</div>
          <div style="display: flex; gap: 10px; align-items: center;">
            ${nvdLink ? `
              <a href="${escapeHtml(nvdLink)}" target="_blank" class="external-link nvd-link" title="View on NVD">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                  <path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                </svg>
                NVD
              </a>
            ` : ''}
            ${ghsaLink ? `
              <a href="${escapeHtml(ghsaLink)}" target="_blank" class="external-link github-link" title="View on GitHub Advisory">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                GHSA
              </a>
            ` : ''}
            <span class="severity-badge severity-${result.severity}">${result.severity}</span>
          </div>
        </div> <!-- zamykamy vuln-header tutaj -->

        <div class="meta">
          <span>📦 <code>${escapeHtml(result.package)}@${escapeHtml(result.version)}</code></span>
          <span>🏷️ ${escapeHtml(result.ecosystem)}</span>
          ${result.knownExploited ? '<span class="severity-badge severity-critical">🔥 Known exploited (CISA KEV)</span>' : ''}
          ${result.epss !== undefined ? `<span>🎯 EPSS: ${(result.epss * 100).toFixed(1)}%</span>` : ''}
          ${result.cvssScore ? `<span>📊 CVSS: ${result.cvssScore}</span>` : ''}
          ${result.fixedVersion ? `<span>✅ Fixed: ${escapeHtml(result.fixedVersion)}</span>` : ''}
          ${fix?.fixAvailable ? `<span style="color: #2e7d32;">🔧 Fix Available: ${escapeHtml(fix.recommendedVersion)}</span>` : ''}
        </div>

        <div class="summary-text">${escapeHtml(result.summary)}</div>

        ${result.references.length > 0 ? `
          <div class="references">
            <strong>References:</strong>
            ${result.references.filter(safeUrl).slice(0, 3).map(ref => `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref)}</a>`).join('')}
          </div>
        ` : ''}
      </div>
    `}).join('')}

    ${skippedResults.length > 0 ? `
      <div class="skipped-section">
        <h2>⏭️ Ignored Vulnerabilities</h2>
        ${Object.entries(
      skippedResults.reduce((acc, vuln) => {
        if (!acc[vuln.package]) acc[vuln.package] = [];
        acc[vuln.package].push(vuln);
        return acc;
      }, {} as Record<string, typeof skippedResults>)
    ).map(([pkg, vulns]) => `
          <div class="skipped-package">
            <h3><code>${escapeHtml(pkg)}</code> - ${vulns.length} vulnerabilities ignored</h3>
            ${vulns.map(v => `
              <div class="skipped-vuln">
                ${getSeverityIcon(v.severity)} <strong>${escapeHtml(v.cveId)}</strong> (${v.severity}): ${escapeHtml(v.summary.substring(0, 100))}...
              </div>
            `).join('')}
          </div>
        `).join('')}
      </div>
    ` : ''}
  </div>
</body>
</html>`;

  return writeReport(config, 'html', html);
}

function getSeverityIcon(severity: string): string {
  const icons: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
    unknown: "⚪",
  };
  return icons[severity] || "⚪";
}

function generateNVDLink(cveId: string, references: string[]): string | null {
  if (cveId.startsWith('CVE-')) {
    return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  }

  if (cveId.startsWith('GHSA-')) {
    const nvdRef = references.find(ref => ref.includes('nvd.nist.gov/vuln/detail/'));
    if (nvdRef) {
      return nvdRef;
    }

    const cveRef = references.find(ref => ref.includes('CVE-'));
    if (cveRef) {
      const match = cveRef.match(/CVE-\d{4}-\d+/i);
      if (match) {
        return `https://nvd.nist.gov/vuln/detail/${match[0]}`;
      }
    }

    return null;
  }

  // Unknown format
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}

function generateGHSALink(cveId: string, references: string[], ghsaId?: string): string | null {
  if (ghsaId && ghsaId.startsWith('GHSA-')) {
    return `https://github.com/advisories/${ghsaId}`;
  }
  const ghsaRef = references.find(ref =>
    ref.includes('github.com/advisories/GHSA-') ||
    ref.includes('github.com/security/advisory/GHSA-')
  );
  if (ghsaRef) {
    const match = ghsaRef.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
    if (match) {
      return `https://github.com/advisories/${match[0]}`;
    }
  }

  if (cveId.startsWith('GHSA-')) {
    return `https://github.com/advisories/${cveId}`;
  }

  return `https://github.com/advisories?query=${cveId}`;
}

function generateFixSuggestionsHTML(fixSuggestions: FixSuggestion[]): string {
  const fixable = fixSuggestions.filter(f => f.fixAvailable);
  const notFixable = fixSuggestions.filter(f => !f.fixAvailable);

  let html = '<div class="fix-section">';
  html += '<h2>🔧 Fix Suggestions</h2>';

  if (fixable.length > 0) {
    for (const { id, label } of ECOSYSTEMS) {
      const fixes = fixable.filter(f => f.ecosystem === id);
      if (fixes.length === 0) continue;

      html += `<h3>📦 ${escapeHtml(label)}</h3>`;
      html += '<div class="fix-commands">';
      html += '# Run these commands to fix vulnerabilities:<br>';
      fixes.forEach(fix => {
        html += `${escapeHtml(fix.command)}<br>`;
      });
      html += '</div>';

      html += '<table class="fix-table">';
      html += '<tr><th>Package</th><th>Current</th><th>Recommended</th><th>CVEs</th><th>Notes</th></tr>';
      fixes.forEach(fix => {
        html += '<tr>';
        html += `<td><code>${escapeHtml(fix.package)}</code></td>`;
        html += `<td>${escapeHtml(fix.currentVersion)}</td>`;
        html += `<td><strong>${escapeHtml(fix.recommendedVersion)}</strong></td>`;
        html += `<td>${fix.vulnerabilityCount}</td>`;
        html += `<td><span class="fix-badge ${fix.breakingChange ? 'breaking' : 'safe'}">${escapeHtml(fix.reason)}</span></td>`;
        html += '</tr>';
      });
      html += '</table>';
    }
  }

  if (notFixable.length > 0) {
    html += '<div class="no-fix-section">';
    html += `<h3>⚠️ No Fix Available (${notFixable.length})</h3>`;
    html += '<table class="fix-table">';
    html += '<tr><th>Package</th><th>Current Version</th><th>Reason</th></tr>';
    notFixable.forEach(fix => {
      html += '<tr>';
      html += `<td><code>${escapeHtml(fix.package)}</code></td>`;
      html += `<td>${escapeHtml(fix.currentVersion)}</td>`;
      html += `<td>${escapeHtml(fix.reason || 'Unknown')}</td>`;
      html += '</tr>';
    });
    html += '</table>';
    html += '<p><strong>💡 Recommendations:</strong></p>';
    html += '<ul>';
    html += '<li>Check for alternative packages</li>';
    html += '<li>Monitor package repository for updates</li>';
    html += '<li>Consider implementing workarounds</li>';
    html += '<li>Use <code>--skip</code> flag if risk is accepted</li>';
    html += '</ul>';
    html += '</div>';
  }

  html += '</div>';
  return html;
}