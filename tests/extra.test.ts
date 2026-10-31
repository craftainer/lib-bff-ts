import { describe, expect, it } from "vitest";
import { increment } from "../src/extra.ts";

describe("increment", () => {
  it("adds one", () => {
    expect(increment(41)).toBe(42);
  });
});
