import { readFileSync } from "node:fs";
import type { EcosystemDefinition } from "../types.js";
import { dedupeDependencies, findFiles, parseTomlLockPackages } from "../files.js";
import { fetchText } from "../utils.js";

/** Path of a crate in the crates.io sparse index. */
function indexPath(name: string): string {
  const n = name.toLowerCase();
  if (n.length <= 2) return `${n.length}/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

export const cargo: EcosystemDefinition = {
  id: "cargo",
  label: "Rust Crates",
  osvName: "crates.io",
  normalizeName: name => name.toLowerCase(),
  // Cargo.lock does not distinguish direct from transitive dependencies, so --scanType has no effect here.
  detect(projectPath) {
    return dedupeDependencies(
      findFiles(projectPath, name => name === "Cargo.lock").flatMap(path => {
        console.log(`📦 Detected Rust lockfile: ${path}`);
        // Workspace members and git/path dependencies have no registry source.
        return parseTomlLockPackages(readFileSync(path, "utf-8"))
          .filter(p => p.source?.includes("registry+"))
          .map(p => ({ name: p.name, version: p.version, ecosystem: "cargo" as const }));
      })
    );
  },
  registry: {
    async versions(name) {
      const index = await fetchText(`https://index.crates.io/${indexPath(name)}`);
      return index
        .split("\n")
        .filter(Boolean)
        .map(line => JSON.parse(line) as { vers: string; yanked: boolean })
        .filter(entry => !entry.yanked)
        .map(entry => entry.vers);
    },
    command: (name, version) => `cargo update -p ${name} --precise ${version}`,
  },
};
