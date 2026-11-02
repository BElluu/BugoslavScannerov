import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseCsprojPackageReferences,
  parseDotNetDependencies,
  parseNpmDependencies,
  resolveNpmSpec,
  resolveNuGetVersion,
} from "../src/parsers.js";

const tmp = () => mkdtempSync(join(tmpdir(), "bugoslav-"));
const write = (dir: string, name: string, content: unknown) =>
  writeFileSync(join(dir, name), typeof content === "string" ? content : JSON.stringify(content));
const label = (deps: Array<{ name: string; version: string }>) => deps.map(d => `${d.name}@${d.version}`).sort();

describe("version specs", () => {
  test("npm single-comparator specs resolve to a lower bound", () => {
    expect(resolveNpmSpec("^1.2.3")).toBe("1.2.3");
    expect(resolveNpmSpec(">=2.0")).toBe("2.0.0");
    expect(resolveNpmSpec("~1.0.0-beta.1")).toBe("1.0.0-beta.1");
  });
  test("npm ranges, tags and non-registry specs are rejected", () => {
    for (const spec of ["*", "latest", ">=1 <2", "1.x", "git+https://x/y.git", "file:../y", "workspace:*"]) {
      expect(resolveNpmSpec(spec)).toBeUndefined();
    }
  });
  test("NuGet exact, bracketed and range specs", () => {
    expect(resolveNuGetVersion("1.2.3")).toBe("1.2.3");
    expect(resolveNuGetVersion("[1.2.3]")).toBe("1.2.3");
    expect(resolveNuGetVersion("[1.0,2.0)")).toBe("1.0");
    expect(resolveNuGetVersion("1.*")).toBeUndefined();
    expect(resolveNuGetVersion("$(SomeVersion)")).toBeUndefined();
  });
});

describe("npm", () => {
  const lock = {
    packages: {
      "": {},
      "node_modules/a": { version: "1.0.0" },
      "node_modules/a/node_modules/b": { version: "2.0.0" },
      "node_modules/@s/c": { version: "3.0.0" },
      "packages/local": { version: "9.9.9" },
      "node_modules/linked": { link: true },
    },
  };
  test("all: keeps nested packages by their real name, drops workspaces and links", () => {
    const dir = tmp();
    write(dir, "package.json", { dependencies: { a: "^1.0.0" } });
    write(dir, "package-lock.json", lock);
    expect(label(parseNpmDependencies(dir, "all"))).toEqual(["@s/c@3.0.0", "a@1.0.0", "b@2.0.0"]);
  });
  test("fast: resolves direct dependencies to exact versions from the lockfile", () => {
    const dir = tmp();
    write(dir, "package.json", { dependencies: { a: "^0.5.0" }, devDependencies: { "@s/c": "*" } });
    write(dir, "package-lock.json", lock);
    expect(label(parseNpmDependencies(dir, "fast"))).toEqual(["@s/c@3.0.0", "a@1.0.0"]);
  });
  test("without a lockfile falls back to package.json and skips unresolvable specs", () => {
    const dir = tmp();
    write(dir, "package.json", { dependencies: { a: "^1.2.0", b: "latest" } });
    expect(parseNpmDependencies(dir, "fast")).toEqual([{ name: "a", version: "1.2.0", ecosystem: "npm" }]);
  });
});

describe(".NET", () => {
  test("PackageReference in any attribute order, child <Version>, and central versions", () => {
    const csproj = `
      <PackageReference Version="1.0.0" Include="A" />
      <PackageReference Include="B"><Version>2.0.0</Version></PackageReference>
      <PackageReference Include="C" />
      <PackageReference Include="D" Version="$(V)" />`;
    const deps = parseCsprojPackageReferences(csproj, new Map([["c", "3.0.0"]]));
    expect(label(deps)).toEqual(["A@1.0.0", "B@2.0.0", "C@3.0.0"]);
  });
  test("reads packages.lock.json next to the project; fast keeps only direct packages", () => {
    const dir = tmp();
    mkdirSync(join(dir, "App"));
    write(join(dir, "App"), "App.csproj", "<Project/>");
    write(join(dir, "App"), "packages.lock.json", {
      dependencies: {
        "net8.0": {
          X: { type: "Direct", resolved: "1.0.0" },
          Y: { type: "Transitive", resolved: "2.0.0" },
          Lib: { type: "Project" },
        },
      },
    });
    const csproj = join(dir, "App", "App.csproj");
    expect(parseDotNetDependencies(csproj, "all").map(d => d.name).sort()).toEqual(["X", "Y"]);
    expect(parseDotNetDependencies(csproj, "fast").map(d => d.name)).toEqual(["X"]);
  });
  test("Directory.Packages.props in a parent folder supplies versions", () => {
    const dir = tmp();
    write(dir, "Directory.Packages.props", `<Project><ItemGroup><PackageVersion Include="Z" Version="4.0.0" /></ItemGroup></Project>`);
    write(dir, "App.csproj", `<Project><ItemGroup><PackageReference Include="Z" /></ItemGroup></Project>`);
    expect(parseDotNetDependencies(join(dir, "App.csproj"), "fast")).toEqual([{ name: "Z", version: "4.0.0", ecosystem: "nuget" }]);
  });
});
