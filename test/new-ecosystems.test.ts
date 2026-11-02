import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseTomlLockPackages } from "../src/files.js";
import { ECOSYSTEMS } from "../src/ecosystems/index.js";
import { normalizePyPIName, parseRequirements } from "../src/ecosystems/pypi.js";
import { parseGoMod } from "../src/ecosystems/go.js";
import { compareVersions, isAffectedByEvents } from "../src/version.js";
import { convertOSVToResult } from "../src/osv.js";

const tmp = () => mkdtempSync(join(tmpdir(), "bugoslav-"));
const label = (deps: Array<{ name: string; version: string }>) => deps.map(d => `${d.name}@${d.version}`).sort();
const detect = (id: string, dir: string, scanType: "all" | "fast" = "all") =>
  ECOSYSTEMS.find(e => e.id === id)!.detect(dir, scanType);

describe("ecosystem registry", () => {
  test("ids are unique and every ecosystem has an OSV name", () => {
    expect(new Set(ECOSYSTEMS.map(e => e.id)).size).toBe(ECOSYSTEMS.length);
    expect(ECOSYSTEMS.map(e => e.osvName)).toEqual(["npm", "NuGet", "PyPI", "Go", "crates.io"]);
  });
  test("registry commands", () => {
    const command = (id: string, version: string) => ECOSYSTEMS.find(e => e.id === id)!.registry.command("pkg", version);
    expect(command("npm", "1.2.3")).toBe("npm install pkg@1.2.3");
    expect(command("nuget", "1.2.3")).toBe("dotnet add package pkg --version 1.2.3");
    expect(command("pypi", "1.2.3")).toBe('pip install "pkg==1.2.3"');
    expect(command("go", "1.2.3")).toBe("go get pkg@v1.2.3");
    expect(command("go", "v1.2.3")).toBe("go get pkg@v1.2.3");
    expect(command("cargo", "1.2.3")).toBe("cargo update -p pkg --precise 1.2.3");
  });
});

describe("Python", () => {
  test("requirements: exact pins only; extras, markers, hashes, comments handled", () => {
    const { deps, unpinned } = parseRequirements(
      [
        "# comment",
        "Django==2.0  # inline",
        "requests[security]==2.19.0 ; python_version >= '3'",
        "My_Package.Name===1.0",
        "pinned==1.0 \\",
        "    --hash=sha256:abc",
        "flask>=1.0",
        "-r other.txt",
        "-e .",
        "",
      ].join("\n")
    );
    expect(label(deps)).toEqual(["django@2.0", "my-package-name@1.0", "pinned@1.0", "requests@2.19.0"]);
    expect(unpinned).toEqual(["flask>=1.0"]);
  });
  test("names are normalised per PEP 503", () => {
    expect(normalizePyPIName("Foo_Bar.baz")).toBe("foo-bar-baz");
  });
  test("poetry.lock skips packages from other sources; uv.lock keeps registry packages only", () => {
    const dir = tmp();
    mkdirSync(join(dir, "a"));
    mkdirSync(join(dir, "b"));
    writeFileSync(
      join(dir, "a", "poetry.lock"),
      [
        '[[package]]\nname = "Django"\nversion = "2.0"\n\n[package.dependencies]\npytz = "*"\n',
        '[[package]]\nname = "internal"\nversion = "0.1"\n\n[package.source]\ntype = "git"\nurl = "https://x/y.git"\n',
      ].join("\n")
    );
    writeFileSync(
      join(dir, "b", "uv.lock"),
      [
        '[[package]]\nname = "requests"\nversion = "2.19.0"\nsource = { registry = "https://pypi.org/simple" }\n',
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n',
      ].join("\n")
    );
    expect(label(detect("pypi", dir))).toEqual(["django@2.0", "requests@2.19.0"]);
  });
  test("Pipfile.lock pins", () => {
    const dir = tmp();
    writeFileSync(join(dir, "Pipfile.lock"), JSON.stringify({ default: { Flask: { version: "==1.0" } }, develop: { pytest: { version: "==7.0.0" } } }));
    expect(label(detect("pypi", dir))).toEqual(["flask@1.0", "pytest@7.0.0"]);
  });
  test("ignores virtual environments", () => {
    const dir = tmp();
    mkdirSync(join(dir, ".venv"));
    writeFileSync(join(dir, ".venv", "requirements.txt"), "x==1.0");
    expect(detect("pypi", dir)).toEqual([]);
  });
});

describe("Go", () => {
  const mod = `module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.6.0

require (
\tgolang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
\tgolang.org/x/text v0.3.0 // indirect
)

replace example.com/x => ../x

exclude (
\tgithub.com/bad/pkg v1.0.0
)
`;
  test("reads single and block requires, ignores replace/exclude", () => {
    expect(label(parseGoMod(mod, "all"))).toEqual([
      "github.com/gin-gonic/gin@1.6.0",
      "golang.org/x/crypto@0.0.0-20200622213623-75b288015ac9",
      "golang.org/x/text@0.3.0",
    ]);
  });
  test("fast skips indirect dependencies", () => {
    expect(parseGoMod(mod, "fast").map(d => d.name)).toEqual(["github.com/gin-gonic/gin", "golang.org/x/crypto"]);
  });
});

describe("Rust", () => {
  test("Cargo.lock keeps registry crates, drops workspace members and git sources", () => {
    const dir = tmp();
    writeFileSync(
      join(dir, "Cargo.lock"),
      [
        '[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "smallvec",\n]\n',
        '[[package]]\nname = "smallvec"\nversion = "0.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n',
        '[[package]]\nname = "forked"\nversion = "1.0.0"\nsource = "git+https://github.com/x/forked#abcdef"\n',
      ].join("\n")
    );
    expect(label(detect("cargo", dir))).toEqual(["smallvec@0.6.0"]);
  });
  test("TOML lock reader handles CRLF", () => {
    expect(parseTomlLockPackages('[[package]]\r\nname = "a"\r\nversion = "1.0.0"\r\n')).toEqual([
      { name: "a", version: "1.0.0", source: undefined, hasSourceTable: false },
    ]);
  });
});

describe("PEP 440 versions", () => {
  test("pre-release tags attached to the number sort before the release", () => {
    expect(compareVersions("1.0rc1", "1.0")).toBeLessThan(0);
    expect(compareVersions("1.0a1", "1.0b1")).toBeLessThan(0);
    expect(compareVersions("1.0rc2", "1.0rc10")).toBeLessThan(0);
    expect(compareVersions("2.0.dev1", "2.0")).toBeLessThan(0);
    expect(compareVersions("1.10", "1.9")).toBeGreaterThan(0);
  });
  test("range matching with a pre-release fix", () => {
    expect(isAffectedByEvents("2.0rc1", [{ introduced: "0" }, { fixed: "2.0" }])).toBe(true);
    expect(isAffectedByEvents("2.0", [{ introduced: "0" }, { fixed: "2.0" }])).toBe(false);
  });
  test("PyPI package names are matched after normalisation when picking the fix", () => {
    const result = convertOSVToResult(
      { name: "my-package", version: "1.0", ecosystem: "pypi" },
      {
        id: "PYSEC-1",
        affected: [{ package: { name: "My_Package", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.1" }] }] }],
      }
    );
    expect(result.fixedVersion).toBe("1.1");
  });
});
