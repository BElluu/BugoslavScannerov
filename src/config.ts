import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ScanResult } from "./types.js";
import { UsageError } from "./utils.js";

export const DEFAULT_CONFIG_FILE = ".bugoslavrc.json";

export interface IgnoreRule {
  /** CVE or GHSA id of the advisory to ignore. */
  id: string;
  /** Limits the rule to one package (case-insensitive). */
  package?: string;
  /** Why the risk is accepted. Required, so every exception stays reviewable. */
  reason: string;
  /** Last day (YYYY-MM-DD, inclusive) the rule applies; afterwards the finding is reported again. */
  expires?: string;
}

/**
 * Loads ignore rules. Without an explicit path, `.bugoslavrc.json` in the project is used if present.
 * File format: { "ignore": [{ "id": "CVE-2021-23337", "reason": "Not reachable", "expires": "2027-01-31" }] }
 */
export function loadIgnoreRules(projectPath: string, explicitPath?: string): IgnoreRule[] {
  const path = explicitPath ?? join(projectPath, DEFAULT_CONFIG_FILE);
  if (!existsSync(path)) {
    if (explicitPath) throw new UsageError(`Config file not found: ${path}`);
    return [];
  }

  let raw: any;
  try {
    raw = JSON.parse(readFileSync(path, "utf-8"));
  } catch (error) {
    throw new UsageError(`Cannot parse ${path}: ${error instanceof Error ? error.message : error}`);
  }

  const entries: unknown = raw?.ignore ?? [];
  if (!Array.isArray(entries)) throw new UsageError(`${path}: "ignore" must be an array.`);

  return entries.map((entry: any, index) => {
    const where = `${path}: ignore[${index}]`;
    if (typeof entry?.id !== "string" || !entry.id.trim()) throw new UsageError(`${where} needs an "id".`);
    if (typeof entry.reason !== "string" || !entry.reason.trim()) {
      throw new UsageError(`${where} (${entry.id}) needs a "reason".`);
    }
    if (entry.expires !== undefined && !(/^\d{4}-\d{2}-\d{2}$/.test(entry.expires) && !isNaN(Date.parse(entry.expires)))) {
      throw new UsageError(`${where} (${entry.id}): "expires" must be a YYYY-MM-DD date.`);
    }
    if (entry.package !== undefined && typeof entry.package !== "string") {
      throw new UsageError(`${where} (${entry.id}): "package" must be a string.`);
    }
    return { id: entry.id.trim(), package: entry.package, reason: entry.reason, expires: entry.expires };
  });
}

function isExpired(rule: IgnoreRule, today: Date): boolean {
  return rule.expires !== undefined && rule.expires < today.toISOString().slice(0, 10);
}

function matches(rule: IgnoreRule, result: ScanResult): boolean {
  const id = rule.id.toLowerCase();
  const idMatches = result.cveId.toLowerCase() === id || result.ghsaId?.toLowerCase() === id;
  return idMatches && (rule.package === undefined || rule.package.toLowerCase() === result.package.toLowerCase());
}

/** Splits results into kept and ignored ones. Expired rules no longer ignore anything and are returned for a warning. */
export function applyIgnoreRules(results: ScanResult[], rules: IgnoreRule[], today = new Date()) {
  const expired = rules.filter(rule => isExpired(rule, today));
  const active = rules.filter(rule => !expired.includes(rule));

  const kept: ScanResult[] = [];
  const ignored: ScanResult[] = [];
  for (const result of results) {
    (active.some(rule => matches(rule, result)) ? ignored : kept).push(result);
  }
  return { kept, ignored, expired };
}
