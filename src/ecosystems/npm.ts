import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Dependency, EcosystemDefinition, ScanType } from "../types.js";
import { dedupeDependencies, readJson } from "../files.js";
import { fetchJson } from "../utils.js";

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

export function parseNpmDependencies(projectPath: string, scanType: ScanType): Dependency[] {
  const packagePath = join(projectPath, "package.json");
  const lockPath = join(projectPath, "package-lock.json");
  const manifest = existsSync(packagePath) ? readJson(packagePath) : {};
  const declared: Record<string, string> = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.optionalDependencies,
  };
  const directNames = Object.keys(declared);

  if (existsSync(lockPath)) {
    const lock = readJson(lockPath);
    const only = scanType === "fast" ? directNames : undefined;
    const deps = lock.packages ? npmFromLockV2(lock.packages, only) : npmFromLockV1(lock.dependencies ?? {}, only);
    return dedupeDependencies(deps);
  }

  if (scanType === "all") {
    console.warn("⚠️  No package-lock.json found: scanning only direct dependencies from package.json.");
  }
  const deps: Dependency[] = [];
  for (const [name, spec] of Object.entries(declared)) {
    const version = resolveNpmSpec(spec);
    if (version) deps.push({ name, version, ecosystem: "npm" });
    else console.warn(`⚠️  Skipping ${name}@${spec}: cannot resolve to a concrete version without a lockfile.`);
  }
  return dedupeDependencies(deps);
}

function npmFromLockV2(packages: Record<string, any>, onlyNames?: string[]): Dependency[] {
  const only = onlyNames ? new Set(onlyNames) : undefined;
  const deps: Dependency[] = [];
  for (const [path, pkg] of Object.entries(packages)) {
    // Workspace packages and symlinks are not installed from the registry.
    if (path === "" || pkg.link || !path.includes("node_modules/") || !pkg.version) continue;
    const name: string = pkg.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    if (only && !(path === `node_modules/${name}` && only.has(name))) continue;
    deps.push({ name, version: pkg.version, ecosystem: "npm" });
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
  detect(projectPath, scanType) {
    if (!existsSync(join(projectPath, "package.json"))) return [];
    console.log("📦 Detected npm project");
    return parseNpmDependencies(projectPath, scanType);
  },
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
