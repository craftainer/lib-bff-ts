// Example entry point `./extra`: a second `exports` subpath.
import { add } from "./core.ts";

/** Return `value` plus one. */
export function increment(value: number): number {
  return add(value, 1);
}
