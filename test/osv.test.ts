import { afterEach, describe, expect, test } from "bun:test";
import { convertOSVToResult, scanWithOSV } from "../src/osv.js";
import type { Dependency, OSVVulnerability } from "../src/types.js";

const lodash: Dependency = { name: "lodash", version: "4.17.15", ecosystem: "npm" };

const advisory: OSVVulnerability = {
  id: "GHSA-35jh-r3h4-6jhm",
  aliases: ["CVE-2021-23337"],
  summary: "Command Injection in lodash",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
  database_specific: { severity: "HIGH" },
  affected: [
    { package: { name: "lodash-es", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }, { introduced: "5.0.0" }, { fixed: "5.1.0" }] }],
    },
  ],
  references: [{ type: "WEB", url: "https://example.com/a" }],
};

describe("convertOSVToResult", () => {
  test("prefers CVE id, computes CVSS, and uses the fix of the matching package and range", () => {
    const result = convertOSVToResult(lodash, advisory);
    expect(result.cveId).toBe("CVE-2021-23337");
    expect(result.ghsaId).toBe("GHSA-35jh-r3h4-6jhm");
    expect(result.cvssScore).toBe(7.2);
    expect(result.severity).toBe("high");
    expect(result.fixedVersion).toBe("4.17.21");
  });
  test("falls back to database severity, then unknown", () => {
    expect(convertOSVToResult(lodash, { id: "X", severity: [], database_specific: { severity: "MODERATE" } }).severity).toBe("medium");
    expect(convertOSVToResult(lodash, { id: "X" }).severity).toBe("unknown");
  });
  test("summary falls back to first line of details, then id", () => {
    expect(convertOSVToResult(lodash, { id: "X", details: "\n First line\nrest" }).summary).toBe("First line");
    expect(convertOSVToResult(lodash, { id: "X" }).summary).toBe("X");
  });
});

describe("scanWithOSV", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  const mockFetch = (handler: (url: string, body?: any) => { status?: number; json?: unknown }) => {
    globalThis.fetch = (async (input: any, init?: any) => {
      const { status = 200, json } = handler(String(input), init?.body ? JSON.parse(init.body) : undefined);
      return new Response(JSON.stringify(json ?? {}), { status });
    }) as typeof fetch;
  };

  test("fetches advisory details, skips withdrawn ones and follows pagination", async () => {
    const queries: any[] = [];
    mockFetch((url, body) => {
      if (url.endsWith("/querybatch")) {
        queries.push(body.queries[0]);
        return body.queries[0].page_token
          ? { json: { results: [{ vulns: [{ id: "GHSA-old" }] }] } }
          : { json: { results: [{ vulns: [{ id: advisory.id }], next_page_token: "p2" }] } };
      }
      if (url.endsWith("GHSA-old")) return { json: { id: "GHSA-old", withdrawn: "2023-01-01T00:00:00Z" } };
      return { json: advisory };
    });

    const results = await scanWithOSV([lodash]);
    expect(queries).toHaveLength(2);
    expect(results.map(r => r.cveId)).toEqual(["CVE-2021-23337"]);
  });

  test("throws when OSV rejects the request instead of reporting a clean scan", async () => {
    mockFetch(() => ({ status: 400 }));
    await expect(scanWithOSV([lodash])).rejects.toThrow();
  });
});
