import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toCycloneDx } from "../src/cyclonedx.js";
import { ECOSYSTEMS } from "../src/ecosystems/index.js";
import { generateReport } from "../src/reporter.js";
import type { Config, Dependency, ScanResult } from "../src/types.js";

const purl = (id: string, name: string, version: string) => ECOSYSTEMS.find(e => e.id === id)!.purl(name, version);

describe("purl", () => {
  test("per ecosystem", () => {
    expect(purl("npm", "lodash", "4.17.15")).toBe("pkg:npm/lodash@4.17.15");
    expect(purl("npm", "@babel/core", "7.0.0")).toBe("pkg:npm/%40babel/core@7.0.0");
    expect(purl("nuget", "Newtonsoft.Json", "9.0.1")).toBe("pkg:nuget/Newtonsoft.Json@9.0.1");
    expect(purl("pypi", "My_Package", "1.0")).toBe("pkg:pypi/my-package@1.0");
    expect(purl("go", "github.com/gin-gonic/gin", "1.6.0")).toBe("pkg:golang/github.com/gin-gonic/gin@v1.6.0");
    expect(purl("go", "github.com/x/y", "v1.0.0")).toBe("pkg:golang/github.com/x/y@v1.0.0");
    expect(purl("cargo", "smallvec", "0.6.0")).toBe("pkg:cargo/smallvec@0.6.0");
  });
});

describe("CycloneDX", () => {
  const dependencies: Dependency[] = [
    { name: "lodash", version: "4.17.15", ecosystem: "npm", manifest: "package-lock.json" },
    { name: "left-pad", version: "1.3.0", ecosystem: "npm", manifest: "package-lock.json" },
    { name: "lodash", version: "4.17.15", ecosystem: "npm", manifest: "other/package-lock.json" },
    { name: "Django", version: "2.0", ecosystem: "pypi" },
  ];
  const make = (over: Partial<ScanResult>): ScanResult => ({
    package: "lodash",
    version: "4.17.15",
    ecosystem: "npm",
    cveId: "CVE-2021-23337",
    ghsaId: "GHSA-35jh-r3h4-6jhm",
    severity: "high",
    cvssScore: 7.2,
    summary: "Command Injection in lodash",
    references: ["javascript:alert(1)", "https://example.com/advisory"],
    fixedVersion: "4.17.21",
    knownExploited: false,
    epss: 0.21,
    publishedDate: "2021-02-15T13:15:00Z",
    ...over,
  });
  const bom = toCycloneDx(dependencies, [make({}), make({ package: "Django", version: "2.0", ecosystem: "pypi", fixedVersion: "2.2.28" })], {
    toolVersion: "9.9.9",
    projectName: "demo",
    now: new Date("2026-01-01T00:00:00Z"),
    serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
  });

  test("document header and metadata", () => {
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.5");
    expect(bom.metadata.timestamp).toBe("2026-01-01T00:00:00.000Z");
    expect(bom.metadata.component.name).toBe("demo");
    expect(bom.metadata.tools.components[0].version).toBe("9.9.9");
  });
  test("lists every dependency once, vulnerable or not, with its manifest", () => {
    expect(bom.components.map((c: any) => c.purl)).toEqual([
      "pkg:npm/lodash@4.17.15",
      "pkg:npm/left-pad@1.3.0",
      "pkg:pypi/django@2.0",
    ]);
    expect((bom.components[0] as any).evidence.occurrences[0].location).toBe("package-lock.json");
  });
  test("one vulnerability per advisory affecting every vulnerable component", () => {
    expect(bom.vulnerabilities).toHaveLength(1);
    const v: any = bom.vulnerabilities[0];
    expect(v.id).toBe("CVE-2021-23337");
    expect(v.affects.map((a: any) => a.ref)).toEqual(["pkg:npm/lodash@4.17.15", "pkg:pypi/django@2.0"]);
    expect(v.recommendation).toBe("Upgrade lodash to 4.17.21; Django to 2.2.28.");
    expect(v.ratings[0]).toMatchObject({ severity: "high", score: 7.2 });
    expect(v.references[0].id).toBe("GHSA-35jh-r3h4-6jhm");
    expect(v.advisories).toEqual([{ url: "https://example.com/advisory" }]);
    expect(v.properties).toEqual([
      { name: "cisa:kev", value: "false" },
      { name: "first:epss", value: "0.21" },
    ]);
  });
  test("every affected ref is a component", () => {
    const refs = new Set(bom.components.map((c: any) => c["bom-ref"]));
    for (const v of bom.vulnerabilities as any[]) for (const a of v.affects) expect(refs.has(a.ref)).toBe(true);
  });
  test("reporter writes .cdx.json including all scanned dependencies", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bugoslav-"));
    const config: Config = {
      scanType: "all", outputFormat: "cyclonedx", outputPath: join(dir, "sbom"),
      skipPackages: [], suggestFixes: false, failOn: "low", enrich: false,
    };
    const path = await generateReport([], config, [], undefined, { dependencies, projectName: "demo" });
    expect(path.endsWith("sbom.cdx.json")).toBe(true);
    const written = JSON.parse(readFileSync(path, "utf8"));
    expect(written.components).toHaveLength(3);
    expect(written.vulnerabilities).toEqual([]);
    expect(written.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });
});
