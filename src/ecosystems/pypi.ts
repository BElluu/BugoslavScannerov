import { readFileSync } from "node:fs";
import type { Dependency, EcosystemDefinition } from "../types.js";
import { dedupeDependencies, findFiles, parseTomlLockPackages, readJson } from "../files.js";
import { fetchJson } from "../utils.js";

/** PEP 503 name normalisation. */
export const normalizePyPIName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

const dep = (name: string, version: string): Dependency => ({ name: normalizePyPIName(name), version, ecosystem: "pypi" });

/**
 * Reads exact pins (`name==1.2.3`, extras and environment markers allowed) from a requirements file.
 * Unpinned requirements cannot be matched against advisories and are returned in `unpinned`.
 */
export function parseRequirements(content: string): { deps: Dependency[]; unpinned: string[] } {
  const deps: Dependency[] = [];
  const unpinned: string[] = [];

  const lines = content.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.replace(/(^|\s)#.*$/, "").split(";")[0].replace(/\s--hash=\S+/g, "").trim();
    if (!line || line.startsWith("-")) continue;

    const pinned = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.!+_-]+)$/);
    if (pinned) deps.push(dep(pinned[1], pinned[2]));
    else unpinned.push(line);
  }
  return { deps, unpinned };
}

function parseRequirementsFile(path: string): Dependency[] {
  const { deps, unpinned } = parseRequirements(readFileSync(path, "utf-8"));
  if (unpinned.length > 0) {
    console.warn(`⚠️  ${path}: ${unpinned.length} requirement(s) are not pinned with == and were skipped.`);
  }
  return deps;
}

function parsePipfileLock(path: string): Dependency[] {
  const lock = readJson(path);
  return ["default", "develop"].flatMap(section =>
    Object.entries<any>(lock[section] ?? {}).flatMap(([name, info]) =>
      typeof info.version === "string" && info.version.startsWith("==") ? [dep(name, info.version.slice(2))] : []
    )
  );
}

const isManifest = (name: string) =>
  name === "poetry.lock" || name === "uv.lock" || name === "Pipfile.lock" || /^requirements.*\.txt$/i.test(name);

function parseManifest(path: string): Dependency[] {
  const name = path.split(/[\\/]/).pop()!;
  if (name === "Pipfile.lock") return parsePipfileLock(path);
  if (name === "poetry.lock") {
    // Packages from git, directories or private indexes carry a [package.source] table.
    return parseTomlLockPackages(readFileSync(path, "utf-8")).filter(p => !p.hasSourceTable).map(p => dep(p.name, p.version));
  }
  if (name === "uv.lock") {
    return parseTomlLockPackages(readFileSync(path, "utf-8"))
      .filter(p => p.source?.includes("registry"))
      .map(p => dep(p.name, p.version));
  }
  return parseRequirementsFile(path);
}

export const pypi: EcosystemDefinition = {
  id: "pypi",
  label: "Python Packages",
  osvName: "PyPI",
  normalizeName: normalizePyPIName,
  // Lockfiles do not distinguish direct from transitive dependencies, so --scanType has no effect here.
  detect(projectPath) {
    return dedupeDependencies(
      findFiles(projectPath, isManifest).flatMap(path => {
        console.log(`📦 Detected Python manifest: ${path}`);
        return parseManifest(path);
      })
    );
  },
  registry: {
    async versions(name) {
      // PEP 700: the JSON simple API lists all versions without per-file metadata.
      const data = await fetchJson<{ versions?: string[] }>(`https://pypi.org/simple/${normalizePyPIName(name)}/`, {
        headers: { Accept: "application/vnd.pypi.simple.v1+json" },
      });
      return data.versions ?? [];
    },
    command: (name, version) => `pip install "${name}==${version}"`,
  },
};
