import { defineConfig } from "tsdown";

// ESM only. Each entry becomes a package.json `exports` subpath: keep this map
// and package.json's `exports` in step (publint and attw verify the result).
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: "esm",
  tsconfig: "tsconfig.build.json",
  dts: true,
  clean: true,
  sourcemap: true,
});
