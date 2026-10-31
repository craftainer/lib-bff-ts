import { describe, expect, it } from "vitest";
import { PACKAGE_NAME } from "../src/index.ts";

describe("index", () => {
  it("exports the package name", () => {
    expect(PACKAGE_NAME).toBe("@craftainer/bff");
  });
});
