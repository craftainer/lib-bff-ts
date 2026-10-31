import { describe, expect, it } from "vitest";
import { total } from "../src/index.ts";

describe("total", () => {
  it("sums the values", () => {
    expect(total([1, 2, 3])).toBe(6);
  });

  it("returns 0 when empty", () => {
    expect(total([])).toBe(0);
  });
});
