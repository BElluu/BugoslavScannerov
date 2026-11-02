import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deduplicateResults, filterSkippedPackages, shouldFail } from "../src/results.js";
import { generateReport } from "../src/reporter.js";
import { escapeHtml, safeUrl } from "../src/utils.js";
import type { Config, ScanResult } from "../src/types.js";

const make = (over: Partial<ScanResult>): ScanResult => ({
  package: "p",
  version: "1.0.0",
  ecosystem: "npm",
  cveId: "CVE-1",
  severity: "low",
  summary: "s",
  references: [],
  ...over,
});

describe("results", () => {
  test("deduplicates per package version and CVE keeping the most severe, KEV first", () => {
    const out = deduplicateResults([
      make({ severity: "low" }),
      make({ severity: "high" }),
      make({ cveId: "CVE-2", severity: "critical" }),
      make({ cveId: "CVE-3", severity: "low", knownExploited: true }),
      make({ version: "2.0.0", severity: "low" }),
    ]);
    expect(out.map(r => `${r.cveId}:${r.version}:${r.severity}`)).toEqual([
      "CVE-3:1.0.0:low",
      "CVE-2:1.0.0:critical",
      "CVE-1:1.0.0:high",
      "CVE-1:2.0.0:low",
    ]);
  });
  test("skip list is case-insensitive", () => {
    expect(filterSkippedPackages([make({ package: "Foo" }), make({ package: "bar" })], ["foo"]).map(r => r.package)).toEqual(["bar"]);
  });
  test("shouldFail honours the threshold; unknown ranks as medium", () => {
    const high = [make({ severity: "high" })];
    expect(shouldFail(high, "critical")).toBe(false);
    expect(shouldFail(high, "high")).toBe(true);
    expect(shouldFail(high, "none")).toBe(false);
    expect(shouldFail([make({ severity: "unknown" })], "medium")).toBe(true);
    expect(shouldFail([make({ severity: "unknown" })], "high")).toBe(false);
    expect(shouldFail([], "low")).toBe(false);
  });
});

describe("HTML report", () => {
  test("escapes untrusted advisory data and drops non-http links", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bugoslav-"));
    const config: Config = {
      scanType: "all",
      outputFormat: "html",
      outputPath: join(dir, "out", "report"),
      skipPackages: [],
      suggestFixes: false,
      failOn: "low",
      enrich: false,
    };
    const evil = make({
      cveId: 'CVE-1"><script>alert(1)</script>',
      summary: "<img src=x onerror=alert(1)>",
      references: ["javascript:alert(1)", 'https://ok.example/"onmouseover="x'],
    });
    const path = await generateReport([evil], config, [evil]);
    expect(path.endsWith("report.html")).toBe(true);
    const html = readFileSync(path, "utf8");
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("javascript:alert");
    expect(html).not.toContain('"onmouseover="');
  });
  test("helpers", () => {
    expect(escapeHtml(`<a href="x">&'`)).toBe("&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    expect(safeUrl("javascript:alert(1)")).toBeUndefined();
    expect(safeUrl("https://a.b")).toBe("https://a.b");
  });
});
