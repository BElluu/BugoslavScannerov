import { readFileSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import type { Dependency, EcosystemDefinition, ScanType } from "../types.js";
import { dedupeDependencies, findFiles, readJson, withManifest } from "../files.js";
import { fetchJson } from "../utils.js";
import { parseBunLock, parsePnpmLock, parseYarnLock, type DeclaredDeps } from "./npm-lockfiles.js";

/**
 * Reduces a package.json version spec to a concrete version. Only single-comparator specs
 * (1.2.3, ^1.2.3, ~1.2, >=1.2.3) resolve, to their lower bound; ranges, tags, git/file/workspace
 * specs return undefined.
 */
export function resolveNpmSpec(spec: string): string | undefined {
  const match = spec.trim().match(/^(?:[\^~]|>=|=)?\s*v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)$/);
  if (!match) return undefined;
  const [core, ...pre] = match[1].split("-");
  const parts = core.split(".");
  while (parts.length < 3) parts.push("0");
  return parts.join(".") + (pre.length ? `-${pre.join("-")}` : "");
}

/** Lockfiles in order of preference when one directory holds several. */
const LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];

function readDeclared(manifestPaths: string[]): DeclaredDeps {
  const declared: DeclaredDeps = new Map();
  for (const path of manifestPaths) {
    const manifest = readJson(path);
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, spec] of Object.entries<unknown>(manifest[field] ?? {})) {
        if (typeof spec === "string") declared.set(name, (declared.get(name) ?? new Set()).add(spec));
      }
    }
  }
  return declared;
}

function readLockfile(lockPath: string, declared: DeclaredDeps, scanType: ScanType): Dependency[] {
  const fast = scanType === "fast";
  const name = basename(lockPath);
  if (name === "package-lock.json") {
    const lock = readJson(lockPath);
    const only = fast ? [...declared.keys()] : undefined;
    return lock.packages ? npmFromLockV2(lock.packages, only) : npmFromLockV1(lock.dependencies ?? {}, only);
  }
  const content = readFileSync(lockPath, "utf-8");
  if (name === "pnpm-lock.yaml") return parsePnpmLock(content, fast);
  if (name === "yarn.lock") return parseYarnLock(content, fast ? declared : undefined);
  return parseBunLock(content, fast);
}

/**
 * Finds every package.json below `projectPath` and reads the dependencies from the nearest lockfile
 * (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock) in the same or a parent directory, so workspace
 * members are covered by their monorepo's lockfile. Packages without a lockfile fall back to their declared ranges.
 */
export function parseNpmDependencies(projectPath: string, scanType: ScanType): Dependency[] {
  const root = resolve(projectPath);
  const files = findFiles(root, name => name === "package.json" || name === "bun.lockb" || LOCKFILES.includes(name));
  const manifests = files.filter(f => basename(f) === "package.json");
  const binaryBunDirs = new Set(files.filter(f => basename(f) === "bun.lockb").map(f => dirname(f)));

  const lockByDir = new Map<string, string>();
  for (const name of LOCKFILES) {
    for (const file of files.filter(f => basename(f) === name)) {
      if (!lockByDir.has(dirname(file))) lockByDir.set(dirname(file), file);
    }
  }
  const nearestLock = (dir: string): string | undefined => {
    for (let d = dir; ; d = dirname(d)) {
      const lock = lockByDir.get(d);
      if (lock) return lock;
      if (d === root || dirname(d) === d) return undefined;
    }
  };

  const membersByLock = new Map<string, string[]>([...lockByDir.values()].map(lock => [lock, []]));
  const unlocked: string[] = [];
  for (const manifest of manifests) {
    const lock = nearestLock(dirname(manifest));
    if (lock) membersByLock.get(lock)!.push(manifest);
    else unlocked.push(manifest);
  }

  const deps: Dependency[] = [];
  for (const [lock, members] of membersByLock) {
    console.log(`📦 Detected npm lockfile: ${lock}`);
    deps.push(...withManifest(readLockfile(lock, readDeclared(members), scanType), root, lock));
  }

  for (const manifest of unlocked) {
    const declared = readDeclared([manifest]);
    if (declared.size === 0) continue;
    console.log(`📦 Detected npm project without lockfile: ${manifest}`);
    if (scanType === "all") {
      const where = relative(root, dirname(manifest)).split(sep).join("/") || ".";
      const hint = binaryBunDirs.has(dirname(manifest)) ? " (bun.lockb is binary; `bun install --save-text-lockfile` creates bun.lock)" : "";
      console.warn(`⚠️  No lockfile found for ${where}: scanning only direct dependencies from package.json${hint}.`);
    }
    const found: Dependency[] = [];
    for (const [name, specs] of declared) {
      for (const spec of specs) {
        const version = resolveNpmSpec(spec);
        if (version) found.push({ name, version, ecosystem: "npm" });
        else console.warn(`⚠️  Skipping ${name}@${spec}: cannot resolve to a concrete version without a lockfile.`);
      }
    }
    deps.push(...withManifest(found, root, manifest));
  }
  return dedupeDependencies(deps);
}

function npmFromLockV2(packages: Record<string, any>, onlyNames?: string[]): Dependency[] {
  const only = onlyNames ? new Set(onlyNames) : undefined;
  const deps: Dependency[] = [];
  const marker = "node_modules/";
  for (const [path, pkg] of Object.entries(packages)) {
    // Workspace packages and symlinks are not installed from the registry.
    if (path === "" || pkg.link || !path.includes(marker) || !pkg.version) continue;
    const at = path.lastIndexOf(marker);
    const pathName = path.slice(at + marker.length);
    // Direct dependencies sit in the root node_modules or in a workspace member's own node_modules.
    if (only && !(only.has(pathName) && !path.slice(0, at).includes(marker))) continue;
    deps.push({ name: pkg.name ?? pathName, version: pkg.version, ecosystem: "npm" });
  }
  return deps;
}

function npmFromLockV1(dependencies: Record<string, any>, onlyNames?: string[]): Dependency[] {
  const only = onlyNames ? new Set(onlyNames) : undefined;
  const deps: Dependency[] = [];
  const walk = (tree: Record<string, any>, topLevel: boolean) => {
    for (const [name, info] of Object.entries(tree)) {
      if (info.version && (!only || (topLevel && only.has(name)))) {
        deps.push({ name, version: info.version, ecosystem: "npm" });
      }
      if (!only && info.dependencies) walk(info.dependencies, false);
    }
  };
  walk(dependencies, true);
  return deps;
}

export const npm: EcosystemDefinition = {
  id: "npm",
  label: "NPM Packages",
  osvName: "npm",
  normalizeName: name => name.toLowerCase(),
  // Scoped names keep the "/" and encode the "@": pkg:npm/%40scope/name@1.0.0
  purl: (name, version) => `pkg:npm/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version)}`,
  detect: parseNpmDependencies,
  registry: {
    async versions(name) {
      // The abbreviated document is much smaller than the full packument.
      const data = await fetchJson<{ versions?: Record<string, unknown> }>(
        `https://registry.npmjs.org/${encodeURIComponent(name)}`,
        { headers: { Accept: "application/vnd.npm.install-v1+json" } }
      );
      return Object.keys(data.versions ?? {});
    },
    command: (name, version) => `npm install ${name}@${version}`,
  },
};
