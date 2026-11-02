import type { Ecosystem, EcosystemDefinition } from "../types.js";
import { cargo } from "./cargo.js";
import { go } from "./go.js";
import { npm } from "./npm.js";
import { nuget } from "./nuget.js";
import { pypi } from "./pypi.js";

/** Every supported ecosystem. To add one, create a definition and list it here. */
export const ECOSYSTEMS: readonly EcosystemDefinition[] = [npm, nuget, pypi, go, cargo];

export function ecosystemById(id: Ecosystem): EcosystemDefinition {
  return ECOSYSTEMS.find(e => e.id === id)!;
}
