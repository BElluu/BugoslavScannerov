interface ParsedVersion {
  core: number[];
  prerelease: string[];
}

function parse(version: string): ParsedVersion {
  const cleaned = version.trim().replace(/^v/i, "").split("+")[0];
  const dash = cleaned.indexOf("-");
  const corePart = dash === -1 ? cleaned : cleaned.slice(0, dash);
  const pre = dash === -1 ? "" : cleaned.slice(dash + 1);
  return {
    core: corePart.split(".").map(p => parseInt(p, 10) || 0),
    prerelease: pre ? pre.toLowerCase().split(".") : [],
  };
}

/**
 * Compares two versions. Works for semver (npm) and NuGet versions: any number of
 * numeric segments (1.2.3.4), pre-release tags, build metadata ignored.
 * Returns <0, 0 or >0.
 */
export function compareVersions(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);

  const length = Math.max(pa.core.length, pb.core.length);
  for (let i = 0; i < length; i++) {
    const diff = (pa.core[i] ?? 0) - (pb.core[i] ?? 0);
    if (diff !== 0) return diff;
  }

  // A version without pre-release is greater than the same version with one.
  if (pa.prerelease.length === 0 || pb.prerelease.length === 0) {
    return pb.prerelease.length - pa.prerelease.length;
  }

  const preLength = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < preLength; i++) {
    const x = pa.prerelease[i];
    const y = pb.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) return Number(x) - Number(y);
    if (xNum) return -1;
    if (yNum) return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

export function majorVersion(version: string): number {
  return parse(version).core[0] ?? 0;
}

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

/** Whether `version` falls inside the affected interval(s) described by OSV range events. */
export function isAffectedByEvents(version: string, events: OsvEvent[]): boolean {
  const key = (e: OsvEvent) => e.introduced ?? e.fixed ?? e.last_affected ?? "0";
  const sorted = [...events].sort((x, y) => compareVersions(key(x), key(y)));

  let affected = false;
  for (const event of sorted) {
    if (event.introduced !== undefined && compareVersions(version, event.introduced) >= 0) affected = true;
    if (event.fixed !== undefined && compareVersions(version, event.fixed) >= 0) affected = false;
    if (event.last_affected !== undefined && compareVersions(version, event.last_affected) > 0) affected = false;
  }
  return affected;
}

/** Smallest `fixed` version above `version` in an affected range, if the range affects `version`. */
export function fixedVersionFromEvents(version: string, events: OsvEvent[]): string | undefined {
  if (!isAffectedByEvents(version, events)) return undefined;
  return events
    .map(e => e.fixed)
    .filter((f): f is string => f !== undefined && compareVersions(f, version) > 0)
    .sort(compareVersions)[0];
}
