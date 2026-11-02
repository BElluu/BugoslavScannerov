import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { Dependency } from "./types.js";

// Dependency, build output, virtual environment and VCS folders never contain the project's own manifests.
const SKIPPED_DIRECTORIES = new Set([
  "node_modules", "bin", "obj", ".git", ".venv", "venv", "__pycache__", "site-packages", "target", "vendor",
]);

/** Recursively finds files below `root` whose name satisfies `match`, skipping dependency and build folders. */
export function findFiles(root: string, match: (fileName: string) => boolean): string[] {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) walk(join(dir, entry.name));
      } else if (match(entry.name)) {
        files.push(join(dir, entry.name));
      }
    }
  };
  walk(root);
  return files.sort();
}

/** Records which manifest (path relative to the project root, with forward slashes) each dependency was read from. */
export function withManifest(deps: Dependency[], projectPath: string, file: string): Dependency[] {
  const manifest = relative(projectPath, file).split(sep).join("/");
  return deps.map(dep => ({ ...dep, manifest }));
}

export function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf-8"));
}

export function dedupeDependencies(deps: Dependency[]): Dependency[] {
  const seen = new Map<string, Dependency>();
  for (const dep of deps) seen.set(`${dep.ecosystem}:${dep.name.toLowerCase()}@${dep.version}`, dep);
  return [...seen.values()];
}

export interface LockPackage {
  name: string;
  version: string;
  /** Value of the top-level `source` key, if any. */
  source?: string;
  /** Whether the entry has a `[package.source]` table (poetry.lock uses it for non-PyPI sources). */
  hasSourceTable: boolean;
}

/**
 * Reads the `[[package]]` entries of a TOML lockfile (Cargo.lock, poetry.lock, uv.lock).
 * Only the few flat keys we need are read, so no TOML parser is required.
 */
export function parseTomlLockPackages(content: string): LockPackage[] {
  const packages: LockPackage[] = [];
  for (const block of content.replace(/\r\n/g, "\n").split(/^\[\[package\]\][ \t]*$/m).slice(1)) {
    const firstTable = block.search(/^\[/m);
    const head = firstTable === -1 ? block : block.slice(0, firstTable);
    const name = head.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = head.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (!name || !version) continue;
    packages.push({
      name,
      version,
      source: head.match(/^source\s*=\s*(.+)$/m)?.[1],
      hasSourceTable: /^\[package\.source\]/m.test(block),
    });
  }
  return packages;
}
