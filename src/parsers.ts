import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, parse as parsePath } from "node:path";
import type { Dependency } from "./types.js";

type ScanType = "all" | "fast";

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf-8"));
}

export function dedupeDependencies(deps: Dependency[]): Dependency[] {
  const seen = new Map<string, Dependency>();
  for (const dep of deps) seen.set(`${dep.ecosystem}:${dep.name.toLowerCase()}@${dep.version}`, dep);
  return [...seen.values()];
}

// ---------------------------------------------------------------- npm

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
  const directNames = Object.keys({
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.optionalDependencies,
  });

  if (existsSync(lockPath)) {
    const lock = readJson(lockPath);
    const deps = lock.packages
      ? npmFromLockV2(lock.packages, scanType === "fast" ? directNames : undefined)
      : npmFromLockV1(lock.dependencies ?? {}, scanType === "fast" ? directNames : undefined);
    return dedupeDependencies(deps);
  }

  if (scanType === "all") {
    console.warn("⚠️  No package-lock.json found: scanning only direct dependencies from package.json.");
  }
  const deps: Dependency[] = [];
  for (const [name, spec] of Object.entries<string>({
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.optionalDependencies,
  })) {
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

// ---------------------------------------------------------------- .NET

/** Normalises a NuGet version spec ("1.2.3", "[1.2.3]", "[1.0,2.0)") to its lower bound. */
export function resolveNuGetVersion(spec: string): string | undefined {
  const cleaned = spec.trim().replace(/^[\[(]/, "").replace(/[\])]$/, "").split(",")[0].trim();
  if (!/^\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(cleaned)) return undefined;
  return cleaned;
}

function xmlAttr(attributes: string, name: string): string | undefined {
  return attributes.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, "i"))?.[1];
}

/** Reads <PackageVersion> entries of the nearest Directory.Packages.props (central package management). */
function centralPackageVersions(startDir: string): Map<string, string> {
  const versions = new Map<string, string>();
  let dir = startDir;
  const root = parsePath(dir).root;
  while (true) {
    const props = join(dir, "Directory.Packages.props");
    if (existsSync(props)) {
      for (const m of readFileSync(props, "utf-8").matchAll(/<PackageVersion\b([^>]*?)\/?>/gi)) {
        const include = xmlAttr(m[1], "Include");
        const version = xmlAttr(m[1], "Version");
        if (include && version) versions.set(include.toLowerCase(), version);
      }
      return versions;
    }
    if (dir === root || dirname(dir) === dir) return versions;
    dir = dirname(dir);
  }
}

export function parseCsprojPackageReferences(content: string, central: Map<string, string>): Dependency[] {
  const deps: Dependency[] = [];
  const references = content.matchAll(/<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/gi);
  for (const m of references) {
    const attributes = m[1];
    const name = xmlAttr(attributes, "Include") ?? xmlAttr(attributes, "Update");
    if (!name) continue;
    const spec =
      xmlAttr(attributes, "VersionOverride") ??
      xmlAttr(attributes, "Version") ??
      m[2]?.match(/<Version>\s*([^<]+?)\s*<\/Version>/i)?.[1] ??
      central.get(name.toLowerCase());
    const version = spec ? resolveNuGetVersion(spec) : undefined;
    if (version) deps.push({ name, version, ecosystem: "nuget" });
    else console.warn(`⚠️  Skipping ${name}${spec ? ` (${spec})` : ""}: version is missing or not a literal.`);
  }
  return deps;
}

export function parseDotNetDependencies(csprojPath: string, scanType: ScanType): Dependency[] {
  const dir = dirname(csprojPath);

  const lockPath = join(dir, "packages.lock.json");
  if (existsSync(lockPath)) {
    const lock = readJson(lockPath);
    const deps: Dependency[] = [];
    for (const packages of Object.values<Record<string, any>>(lock.dependencies ?? {})) {
      for (const [name, info] of Object.entries(packages)) {
        if (!info.resolved || info.type === "Project") continue;
        if (scanType === "fast" && info.type !== "Direct") continue;
        deps.push({ name, version: info.resolved, ecosystem: "nuget" });
      }
    }
    return dedupeDependencies(deps);
  }

  if (scanType === "all") {
    console.warn(`⚠️  No packages.lock.json next to ${csprojPath}: scanning only direct PackageReferences.`);
  }
  const content = readFileSync(csprojPath, "utf-8");
  return dedupeDependencies(parseCsprojPackageReferences(content, centralPackageVersions(dir)));
}

const SKIPPED_DIRECTORIES = new Set(["node_modules", "bin", "obj", ".git"]);

/** Finds .csproj files below `projectPath`, ignoring dependency, build output and VCS folders. */
export function findCsprojFiles(projectPath: string): string[] {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) walk(join(dir, entry.name));
      } else if (entry.name.toLowerCase().endsWith(".csproj")) {
        files.push(join(dir, entry.name));
      }
    }
  };
  walk(projectPath);
  return files.sort();
}
