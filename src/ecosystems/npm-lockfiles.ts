import type { Dependency } from "../types.js";

/** Package name -> the version specs it is declared with in package.json files. */
export type DeclaredDeps = Map<string, Set<string>>;

const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;

const dep = (name: string, version: string): Dependency => ({ name, version, ecosystem: "npm" });

/**
 * Parses a package locator such as `name@1.2.3`, `@scope/name@1.2.3` or `alias@npm:real@1.2.3`.
 * Returns undefined for anything that is not a registry release (git, file, workspace, patch).
 */
function parseLocator(locator: string): { name: string; version: string } | undefined {
  const at = locator.indexOf("@", 1);
  if (at < 0) return undefined;
  let name = locator.slice(0, at);
  let version = locator.slice(at + 1);
  if (version.startsWith("npm:")) {
    version = version.slice(4);
    const inner = version.indexOf("@", 1);
    if (inner > 0) {
      name = version.slice(0, inner);
      version = version.slice(inner + 1);
    }
  }
  return SEMVER.test(version) ? { name, version } : undefined;
}

/** Splits a dependency spec `name@range` (resolving `npm:` aliases); undefined for non-registry ranges. */
function parseSpec(spec: string): { name: string; range: string } | undefined {
  const at = spec.indexOf("@", 1);
  if (at < 0) return undefined;
  let name = spec.slice(0, at);
  let range = spec.slice(at + 1);
  if (range.startsWith("npm:")) {
    range = range.slice(4);
    const inner = range.indexOf("@", 1);
    if (inner > 0) {
      name = range.slice(0, inner);
      range = range.slice(inner + 1);
    }
  }
  // git, file, link, workspace and `user/repo` ranges are not installed from the registry.
  return /[:/]/.test(range) ? undefined : { name, range };
}

/** Reads yarn.lock, both classic (v1) and Berry (v2+). With `declared`, keeps only the declared direct dependencies. */
export function parseYarnLock(content: string, declared?: DeclaredDeps): Dependency[] {
  const berry = /^__metadata:/m.test(content);
  const direct = new Set<string>();
  for (const [name, ranges] of declared ?? []) {
    for (const range of ranges) {
      const spec = parseSpec(`${name}@${range}`);
      if (spec) direct.add(`${spec.name}@${spec.range}`);
    }
  }

  const deps: Dependency[] = [];
  for (const block of content.replace(/\r\n/g, "\n").split(/\n\s*\n/)) {
    const lines = block.split("\n").filter(line => line && !line.startsWith("#"));
    const header = lines[0];
    if (!header || header.startsWith(" ") || !header.endsWith(":") || header.startsWith("__metadata")) continue;

    const specs = header
      .slice(0, -1)
      .replace(/"/g, "")
      .split(/,\s*/)
      .map(parseSpec)
      .filter((s): s is { name: string; range: string } => s !== undefined);
    const find = (re: RegExp) => lines.map(line => line.match(re)?.[1]).find(Boolean);
    const version = find(/^ {2}version:?\s+"?([^"\s]+)"?\s*$/);
    if (!version || specs.length === 0) continue;

    let name = specs[0].name;
    if (berry) {
      // Berry names the resolved package precisely, and marks workspaces and patches with other protocols.
      const locator = find(/^ {2}resolution:\s+"?([^"]+?)"?\s*$/);
      const parsed = locator ? parseLocator(locator) : undefined;
      if (!parsed) continue;
      name = parsed.name;
    }
    if (declared && !specs.some(s => direct.has(`${s.name}@${s.range}`))) continue;
    deps.push(dep(name, version));
  }
  return deps;
}

/** Reads pnpm-lock.yaml (v5 to v9). With `directOnly`, keeps the versions the importers depend on directly. */
export function parsePnpmLock(content: string, directOnly: boolean): Dependency[] {
  const clean = (value: string) => value.trim().replace(/^['"]|['"]$/g, "");
  const packages: Dependency[] = [];
  const direct = new Set<string>();
  const addDirect = (name: string, raw: string) => {
    const version = clean(raw).split("(")[0].split("_")[0];
    if (SEMVER.test(version)) direct.add(`${name}@${version}`);
  };

  let top = "";
  let sectionIndent: number | undefined;
  let pendingName: string | undefined;
  for (const line of content.replace(/\r\n/g, "\n").split("\n")) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      top = line.match(/^([\w-]+):/)?.[1] ?? "";
      sectionIndent = undefined;
      // v5 projects without importers list their dependencies at the top level.
      if (/^(?:dependencies|devDependencies|optionalDependencies):\s*$/.test(line)) sectionIndent = 0;
      continue;
    }

    if (top === "packages") {
      if (indent === 2 && line.trimEnd().endsWith(":")) {
        const parsed = parsePnpmKey(line.trim().slice(0, -1));
        if (parsed) packages.push(dep(parsed.name, parsed.version));
      }
      continue;
    }

    if (!directOnly) continue;
    if (top === "importers" && indent === 4 && /^\s*(?:dependencies|devDependencies|optionalDependencies):\s*$/.test(line)) {
      sectionIndent = 4;
      pendingName = undefined;
      continue;
    }
    if (sectionIndent === undefined) continue;
    if (indent <= sectionIndent) {
      sectionIndent = undefined;
      continue;
    }
    const entry = line.match(/^\s+([^:\s][^:]*):\s*(.*)$/);
    if (!entry) continue;
    const [, key, value] = entry;
    if (key === "specifier") continue;
    if (key === "version") {
      if (pendingName) addDirect(pendingName, value);
      pendingName = undefined;
    } else if (value) {
      addDirect(clean(key), value); // v5: `name: 1.2.3`
    } else {
      pendingName = clean(key); // v6+: version is on a following line
    }
  }

  if (directOnly && direct.size > 0) return packages.filter(p => direct.has(`${p.name}@${p.version}`));
  return packages;
}

/** `/name/1.0.0_peer` (v5) or `name@1.0.0(peer@2.0.0)` (v6+), quotes and leading slash optional. */
function parsePnpmKey(raw: string): { name: string; version: string } | undefined {
  const key = raw.replace(/^['"]|['"]$/g, "").replace(/^\//, "").split("(")[0];
  // The v5 form goes first: its peer suffix (`_react@18.0.0`) would otherwise look like `name@version`.
  const match = key.match(/^(.+)\/(\d[^/_]*)(?:_.*)?$/) ?? key.match(/^(@?[^@]+)@(\d[^@]*)$/);
  return match && SEMVER.test(match[2]) ? { name: match[1], version: match[2] } : undefined;
}

/** bun.lock is JSON with trailing commas; commas inside strings are left alone. */
function stripTrailingCommas(content: string): string {
  return content.replace(/"(?:[^"\\]|\\.)*"|,(\s*[}\]])/g, (match, tail?: string) => (tail === undefined ? match : tail));
}

const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

/** Reads bun.lock (text lockfile, Bun 1.2+). With `directOnly`, keeps packages the workspaces depend on directly. */
export function parseBunLock(content: string, directOnly: boolean): Dependency[] {
  const lock = JSON.parse(stripTrailingCommas(content));
  const workspaces: Array<Record<string, any>> = Object.values(lock.workspaces ?? {});
  const workspaceNames = workspaces.map(w => w.name).filter((n): n is string => typeof n === "string");
  const directNames = new Set(workspaces.flatMap(w => DEPENDENCY_FIELDS.flatMap(field => Object.keys(w[field] ?? {}))));

  const isDirect = (key: string) =>
    directNames.has(key) || workspaceNames.some(ws => key.startsWith(`${ws}/`) && directNames.has(key.slice(ws.length + 1)));

  const deps: Dependency[] = [];
  for (const [key, entry] of Object.entries<any>(lock.packages ?? {})) {
    const parsed = Array.isArray(entry) && typeof entry[0] === "string" ? parseLocator(entry[0]) : undefined;
    if (parsed && (!directOnly || isDirect(key))) deps.push(dep(parsed.name, parsed.version));
  }
  return deps;
}
