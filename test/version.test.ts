import { describe, expect, test } from "bun:test";
import { compareVersions, fixedVersionFromEvents, isAffectedByEvents } from "../src/version.js";
import { cvss3BaseScore } from "../src/cvss.js";

describe("compareVersions", () => {
  test("orders numeric segments numerically, not lexically", () => {
    expect(compareVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareVersions("4.17.21", "4.17.15")).toBeGreaterThan(0);
  });
  test("supports NuGet four-part versions and missing segments", () => {
    expect(compareVersions("1.2.3.4", "1.2.3.3")).toBeGreaterThan(0);
    expect(compareVersions("1.2", "1.2.0.0")).toBe(0);
  });
  test("pre-release is lower than release, and ordered among themselves", () => {
    expect(compareVersions("2.0.0-beta.1", "2.0.0")).toBeLessThan(0);
    expect(compareVersions("2.0.0-beta.2", "2.0.0-beta.10")).toBeLessThan(0);
    expect(compareVersions("2.0.0-alpha", "2.0.0-beta")).toBeLessThan(0);
  });
  test("ignores build metadata and v prefix", () => {
    expect(compareVersions("v1.0.0+build5", "1.0.0")).toBe(0);
  });
});

describe("OSV range events", () => {
  const branches = [{ introduced: "0" }, { fixed: "4.17.21" }, { introduced: "5.0.0" }, { fixed: "5.2.1" }];
  test("detects affected versions across several intervals", () => {
    expect(isAffectedByEvents("4.17.15", branches)).toBe(true);
    expect(isAffectedByEvents("4.17.21", branches)).toBe(false);
    expect(isAffectedByEvents("5.1.0", branches)).toBe(true);
    expect(isAffectedByEvents("5.2.1", branches)).toBe(false);
  });
  test("last_affected is inclusive", () => {
    const events = [{ introduced: "0" }, { last_affected: "1.0.0" }];
    expect(isAffectedByEvents("1.0.0", events)).toBe(true);
    expect(isAffectedByEvents("1.0.1", events)).toBe(false);
  });
  test("fixed version belongs to the interval containing the installed version", () => {
    expect(fixedVersionFromEvents("4.17.15", branches)).toBe("4.17.21");
    expect(fixedVersionFromEvents("5.1.0", branches)).toBe("5.2.1");
    expect(fixedVersionFromEvents("6.0.0", branches)).toBeUndefined();
  });
});

describe("cvss3BaseScore", () => {
  test("matches reference scores", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")).toBe(7.2);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
  });
  test("rejects CVSS v4 and malformed vectors", () => {
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeUndefined();
    expect(cvss3BaseScore("CVSS:3.1/AV:X")).toBeUndefined();
    expect(cvss3BaseScore("7.5")).toBeUndefined();
  });
});
