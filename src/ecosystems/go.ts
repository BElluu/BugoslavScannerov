import { readFileSync } from "node:fs";
import type { Dependency, EcosystemDefinition, ScanType } from "../types.js";
import { dedupeDependencies, findFiles, withManifest } from "../files.js";
import { fetchText } from "../utils.js";

/**
 * Reads `require` directives of a go.mod file. Since Go 1.17 go.mod lists indirect dependencies
 * too, marked `// indirect`; they are skipped for --scanType fast.
 */
export function parseGoMod(content: string, scanType: ScanType): Dependency[] {
  const deps: Dependency[] = [];
  let inRequireBlock = false;

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }

    const body = inRequireBlock ? line : line.match(/^require\s+(.+)$/)?.[1];
    if (!body) continue;

    const match = body.match(/^(\S+)\s+v(\S+)(\s*\/\/\s*indirect)?/);
    if (!match) continue;
    if (scanType === "fast" && match[3]) continue;
    deps.push({ name: match[1], version: match[2], ecosystem: "go" });
  }
  return deps;
}

/** Module proxy paths encode capital letters as "!" plus the lowercase letter. */
const encodeModulePath = (path: string) => path.replace(/[A-Z]/g, ch => `!${ch.toLowerCase()}`);

export const go: EcosystemDefinition = {
  id: "go",
  label: "Go Modules",
  osvName: "Go",
  normalizeName: name => name.toLowerCase(),
  // The purl spec keeps the "v" prefix of Go versions; we store versions without it.
  purl: (name, version) =>
    `pkg:golang/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version.startsWith("v") ? version : `v${version}`)}`,
  detect(projectPath, scanType) {
    return dedupeDependencies(
      findFiles(projectPath, name => name === "go.mod").flatMap(path => {
        console.log(`📦 Detected Go module: ${path}`);
        return withManifest(parseGoMod(readFileSync(path, "utf-8"), scanType), projectPath, path);
      })
    );
  },
  registry: {
    async versions(name) {
      const list = await fetchText(`https://proxy.golang.org/${encodeModulePath(name)}/@v/list`);
      return list.split("\n").map(v => v.trim()).filter(Boolean);
    },
    command: (name, version) => `go get ${name}@${version.startsWith("v") ? version : `v${version}`}`,
  },
};
