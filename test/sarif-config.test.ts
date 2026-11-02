import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyIgnoreRules, loadIgnoreRules } from "../src/config.js";
import { generateReport } from "../src/reporter.js";
import { toSarif } from "../src/sarif.js";
import { ECOSYSTEMS } from "../src/ecosystems/index.js";
import type { Config, ScanResult } from "../src/types.js";

const make = (over: Partial<ScanResult>): ScanResult => ({
  package: "lodash",
  version: "4.17.15",
  ecosystem: "npm",
  manifest: "package-lock.json",
  cveId: "CVE-2021-23337",
  ghsaId: "GHSA-35jh-r3h4-6jhm",
  severity: "high",
  cvssScore: 7.2,
  summary: "Command Injection in lodash",
  references: ["javascript:alert(1)", "https://example.com/advisory"],
  fixedVersion: "4.17.21",
  ...over,
});

const tmp = () => mkdtempSync(join(tmpdir(), "bugoslav-"));

describe("SARIF", () => {
  const sarif = toSarif(
    [make({}), make({ package: "other", cveId: "CVE-2021-23337" }), make({ cveId: "GHSA-low", severity: "low", cvssScore: undefined })],
    "9.9.9"
  );
  const run = sarif.runs[0];

  test("is a SARIF 2.1.0 log with tool metadata", () => {
    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver.name).toBe("Bugoslav Scannerov");
    expect(run.tool.driver.version).toBe("9.9.9");
  });
  test("one rule per advisory, one result per affected dependency", () => {
    expect(run.tool.driver.rules).toHaveLength(2);
    expect(run.results).toHaveLength(3);
  });
  test("rules carry security-severity and a safe help link only", () => {
    const rule: any = run.tool.driver.rules[0];
    expect(rule.properties["security-severity"]).toBe("7.2");
    expect(rule.helpUri).toBe("https://example.com/advisory");
    expect((run.tool.driver.rules[1] as any).properties["security-severity"]).toBe("2.5");
  });
  test("results point at the manifest and have stable fingerprints", () => {
    const [first, second] = run.results;
    expect(first.level).toBe("error");
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe("package-lock.json");
    expect(first.message.text).toContain("Fixed in 4.17.21");
    expect(first.partialFingerprints["bugoslavFinding/v1"]).not.toBe(second.partialFingerprints["bugoslavFinding/v1"]);
    expect(run.results[2].level).toBe("note");
  });
  test("is written by the reporter with the .sarif extension", async () => {
    const dir = tmp();
    const config: Config = {
      scanType: "all", outputFormat: "sarif", outputPath: join(dir, "results"),
      skipPackages: [], suggestFixes: false, failOn: "low", enrich: false,
    };
    const path = await generateReport([make({})], config);
    expect(path.endsWith("results.sarif")).toBe(true);
    expect(JSON.parse(readFileSync(path, "utf8")).runs[0].results).toHaveLength(1);
  });
});

describe("output path", () => {
  test("only a real extension suffix is kept, not a lookalike", async () => {
    const dir = tmp();
    const config: Config = {
      scanType: "all", outputFormat: "json", outputPath: join(dir, "report-json"),
      skipPackages: [], suggestFixes: false, failOn: "low", enrich: false,
    };
    expect((await generateReport([], config)).endsWith("report-json.json")).toBe(true);
    expect((await generateReport([], { ...config, outputPath: join(dir, "x.JSON") })).endsWith("x.JSON")).toBe(true);
  });
});

describe("ignore rules", () => {
  const today = new Date("2026-06-15T12:00:00Z");
  const results = [make({}), make({ package: "other" }), make({ cveId: "CVE-2", ghsaId: undefined })];

  test("matches CVE or GHSA id, case-insensitively, optionally per package", () => {
    const byGhsa = applyIgnoreRules(results, [{ id: "ghsa-35JH-r3h4-6jhm", reason: "r" }], today);
    expect(byGhsa.ignored).toHaveLength(2);
    const scoped = applyIgnoreRules(results, [{ id: "CVE-2021-23337", package: "LODASH", reason: "r" }], today);
    expect(scoped.ignored.map(r => r.package)).toEqual(["lodash"]);
    expect(scoped.kept).toHaveLength(2);
  });
  test("expired rules ignore nothing and are reported; the expiry day itself is still valid", () => {
    const expired = applyIgnoreRules(results, [{ id: "CVE-2", reason: "r", expires: "2026-06-14" }], today);
    expect(expired.ignored).toHaveLength(0);
    expect(expired.expired).toHaveLength(1);
    const lastDay = applyIgnoreRules(results, [{ id: "CVE-2", reason: "r", expires: "2026-06-15" }], today);
    expect(lastDay.ignored).toHaveLength(1);
  });

  test("loads .bugoslavrc.json from the project; missing default file means no rules", () => {
    const dir = tmp();
    expect(loadIgnoreRules(dir)).toEqual([]);
    writeFileSync(join(dir, ".bugoslavrc.json"), JSON.stringify({ ignore: [{ id: "CVE-1", reason: "not reachable", expires: "2030-01-01" }] }));
    expect(loadIgnoreRules(dir)).toEqual([{ id: "CVE-1", package: undefined, reason: "not reachable", expires: "2030-01-01" }]);
  });
  test("rejects rules without a reason, bad dates, bad JSON and missing explicit files", () => {
    const dir = tmp();
    const file = join(dir, "c.json");
    const load = (content: string) => {
      writeFileSync(file, content);
      return () => loadIgnoreRules(dir, file);
    };
    expect(load(JSON.stringify({ ignore: [{ id: "CVE-1" }] }))).toThrow(/reason/);
    expect(load(JSON.stringify({ ignore: [{ id: "CVE-1", reason: "r", expires: "soon" }] }))).toThrow(/YYYY-MM-DD/);
    expect(load(JSON.stringify({ ignore: {} }))).toThrow(/array/);
    expect(load("{nope")).toThrow(/Cannot parse/);
    expect(() => loadIgnoreRules(dir, join(dir, "missing.json"))).toThrow(/not found/);
  });
});

describe("manifest tracking", () => {
  test("dependencies remember the file they came from, relative to the project", () => {
    const dir = tmp();
    mkdirSync(join(dir, "svc"));
    writeFileSync(join(dir, "svc", "go.mod"), "module x\n\nrequire github.com/gin-gonic/gin v1.6.0\n");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { a: "1.0.0" } }));
    const go = ECOSYSTEMS.find(e => e.id === "go")!.detect(dir, "all");
    const npm = ECOSYSTEMS.find(e => e.id === "npm")!.detect(dir, "fast");
    expect(go[0].manifest).toBe("svc/go.mod");
    expect(npm[0].manifest).toBe("package.json");
  });
});
