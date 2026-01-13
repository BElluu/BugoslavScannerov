import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Dependency } from "./types.js";

export async function parseNpmDependencies(projectPath: string, scanType: "all" | "fast"): Promise<Dependency[]> {
  const dependencies: Dependency[] = [];

  
  const lockPath = join(projectPath, "package-lock.json");
  if (existsSync(lockPath) && scanType === "all") {
    const lockContent = JSON.parse(readFileSync(lockPath, "utf-8"));
    
    if (lockContent.packages) {
      // npm v7+ format
      for (const [path, pkg] of Object.entries(lockContent.packages)) {
        if (path === "") continue; // Skip root
        const name = path.replace("node_modules/", "");
        const version = (pkg as any).version;
        if (name && version) {
          dependencies.push({ name, version, ecosystem: "npm" });
        }
      }
    } else if (lockContent.dependencies) {
      // npm v6 format
      flattenDependencies(lockContent.dependencies, dependencies);
    }
    
    return dependencies;
  }
  
  // Fallback to package.json
  const packagePath = join(projectPath, "package.json");
  if (existsSync(packagePath)) {
    const packageJson = JSON.parse(readFileSync(packagePath, "utf-8"));
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    };
    
    for (const [name, version] of Object.entries(allDeps)) {
      // Remove semver prefixes
      const cleanVersion = (version as string).replace(/^[\^~>=<]/, "");
      dependencies.push({ name, version: cleanVersion, ecosystem: "npm" });
    }
  }
  
  return dependencies;
}

function flattenDependencies(deps: any, result: Dependency[]) {
  for (const [name, info] of Object.entries(deps)) {
    const version = (info as any).version;
    if (version) {
      result.push({ name, version, ecosystem: "npm" });
    }
    if ((info as any).dependencies) {
      flattenDependencies((info as any).dependencies, result);
    }
  }
}

export async function parseDotNetDependencies(csprojPath: string): Promise<Dependency[]> {
  const dependencies: Dependency[] = [];
  
  // Try packages.lock.json first
  const lockPath = csprojPath.replace(/\.csproj$/, "") + ".packages.lock.json";
  if (existsSync(lockPath)) {
    const lockContent = JSON.parse(readFileSync(lockPath, "utf-8"));
    
    for (const [framework, deps] of Object.entries(lockContent.dependencies || {})) {
      for (const [name, info] of Object.entries(deps as any)) {
        const version = (info as any).resolved;
        if (version) {
          dependencies.push({ name, version, ecosystem: "nuget" });
        }
      }
    }
    
    return dependencies;
  }
  
  // Fallback to parsing .csproj XML
  const csprojContent = readFileSync(csprojPath, "utf-8");
  const packageReferenceRegex = /<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g;
  
  let match;
  while ((match = packageReferenceRegex.exec(csprojContent)) !== null) {
    dependencies.push({
      name: match[1],
      version: match[2],
      ecosystem: "nuget",
    });
  }
  
  return dependencies;
}