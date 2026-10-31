import type { Valkey } from "iovalkey";
import { describe, expect, it } from "vitest";
import { ValkeyKv, createValkeyKv } from "../src/auth/kv.ts";
import { createValkeySessionStore } from "../src/auth/store.ts";

interface Call {
  method: string;
  args: unknown[];
}

function fake(
  replies: Record<string, unknown> = {},
  status = "ready",
): { client: Valkey; calls: Call[] } {
  const calls: Call[] = [];
  const client = new Proxy(
    { status },
    {
      get(target, prop: string) {
        if (prop === "status") {
          return target.status;
        }
        return (...args: unknown[]) => {
          calls.push({ method: prop, args });
          return prop === "disconnect"
            ? undefined
            : Promise.resolve(replies[prop] ?? null);
        };
      },
    },
  ) as unknown as Valkey;
  return { client, calls };
}

describe("ValkeyKv", () => {
  it("maps each operation to the right command", async () => {
    const { client, calls } = fake({
      set: "OK",
      del: 2,
      pexpire: 1,
      eval: 1,
      smembers: ["a"],
      get: "v",
      getdel: "g",
    });
    const kv = new ValkeyKv(client);
    expect(await kv.get("k")).toBe("v");
    expect(await kv.set("k", "v", { ttlMs: 5 })).toBe(true);
    expect(await kv.set("k", "v", { ttlMs: 5, nx: true })).toBe(true);
    expect(await kv.set("k", "v", { ttlMs: 7.9, onlyIfExists: true })).toBe(
      true,
    );
    expect(await kv.getDel("k")).toBe("g");
    expect(await kv.del("a", "b")).toBe(2);
    expect(await kv.pexpire("k", 9)).toBe(true);
    await kv.sadd("s", "m");
    await kv.srem("s", "m");
    expect(await kv.smembers("s")).toEqual(["a"]);
    expect(await kv.delIfEquals("k", "v")).toBe(true);
    await kv.ping();
    await kv.quit();
    expect(calls.map((c) => [c.method, ...c.args])).toEqual([
      ["get", "k"],
      ["set", "k", "v", "PX", 5],
      ["set", "k", "v", "PX", 5, "NX"],
      ["set", "k", "v", "PX", 7, "XX"],
      ["getdel", "k"],
      ["del", "a", "b"],
      ["pexpire", "k", 9],
      ["sadd", "s", "m"],
      ["srem", "s", "m"],
      ["smembers", "s"],
      [
        "eval",
        expect.stringContaining('redis.call("get", KEYS[1]) == ARGV[1]'),
        1,
        "k",
        "v",
      ],
      ["ping"],
      ["quit"],
    ]);
  });

  it("reports failed NX sets, missing keys and unreleased locks", async () => {
    const { client } = fake({ set: null, pexpire: 0, eval: 0 });
    const kv = new ValkeyKv(client);
    expect(await kv.set("k", "v", { ttlMs: 5, nx: true })).toBe(false);
    expect(await kv.set("k", "v", { ttlMs: 5, onlyIfExists: true })).toBe(
      false,
    );
    expect(await kv.pexpire("k", 1)).toBe(false);
    expect(await kv.delIfEquals("k", "v")).toBe(false);
  });

  it("disconnects instead of QUIT when the connection never became ready", async () => {
    const { client, calls } = fake({}, "wait");
    await new ValkeyKv(client).quit();
    expect(calls.map((c) => c.method)).toEqual(["disconnect"]);
  });
});

describe("createValkeyKv", () => {
  it("builds a lazy client without connecting, for valkey:// and redis:// URLs", async () => {
    for (const url of [
      "valkey://localhost:1",
      "valkeys://localhost:1",
      "redis://localhost:1",
    ]) {
      const kv = createValkeyKv(url);
      await kv.quit();
    }
    const store = createValkeySessionStore("redis://localhost:1", 60);
    await store.close();
  });
});
