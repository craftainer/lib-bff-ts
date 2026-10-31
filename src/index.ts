// Example entry point `.`: replace with the real public API (see docs/TEMPLATE.md).
import { add } from "./core.ts";

/** Return the sum of `values` (0 when empty). */
export function total(values: Iterable<number>): number {
  let result = 0;
  for (const value of values) {
    result = add(result, value);
  }
  return result;
}
