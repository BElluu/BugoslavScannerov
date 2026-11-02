import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse as parsePath } from "node:path";
import type { Dependency, EcosystemDefinition, ScanType } from "../types.js";
import { dedupeDependencies, findFiles, readJson, withManifest } from "../files.js";
import { fetchJson } from "../utils.js";

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
    if (dir === parsePath(dir).root || dirname(dir) === dir) return versions;
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

export const nuget: EcosystemDefinition = {
  id: "nuget",
  label: ".NET Packages",
  osvName: "NuGet",
  normalizeName: name => name.toLowerCase(),
  detect(projectPath, scanType) {
    return findFiles(projectPath, name => name.toLowerCase().endsWith(".csproj")).flatMap(csproj => {
      console.log(`📦 Detected .NET project: ${csproj}`);
      const lock = join(dirname(csproj), "packages.lock.json");
      return withManifest(parseDotNetDependencies(csproj, scanType), projectPath, existsSync(lock) ? lock : csproj);
    });
  },
  registry: {
    async versions(name) {
      const data = await fetchJson<{ versions?: string[] }>(
        `https://api.nuget.org/v3-flatcontainer/${name.toLowerCase()}/index.json`
      );
      return data.versions ?? [];
    },
    command: (name, version) => `dotnet add package ${name} --version ${version}`,
  },
};
