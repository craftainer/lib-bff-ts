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
    expect(await kv.getDel("k")).toBe("g");
    expect(await kv.del("a", "b")).toBe(2);
    expect(await kv.pexpire("k", 9)).toBe(true);
    expect(await kv.smembers("s")).toEqual(["a"]);
    expect(await kv.compareAndSetVersion("k", 3, "{}", 7.9)).toBe(true);
    expect(await kv.delIfEquals("k", "v")).toBe(true);
    await kv.ping();
    await kv.quit();
    expect(calls.map((c) => [c.method, ...c.args])).toEqual([
      ["get", "k"],
      ["set", "k", "v", "PX", 5],
      ["set", "k", "v", "PX", 5, "NX"],
      ["getdel", "k"],
      ["del", "a", "b"],
      ["pexpire", "k", 9],
      ["smembers", "s"],
      ["eval", expect.stringContaining("cjson.decode"), 1, "k", 3, "{}", 7],
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
    expect(await kv.compareAndSetVersion("k", 1, "{}", 5)).toBe(false);
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

describe("ValkeyKv.multi", () => {
  function fakeTx(replies: [Error | null, unknown][] | null): {
    kv: ValkeyKv;
    queued: unknown[][];
  } {
    const queued: unknown[][] = [];
    const tx: Record<string, unknown> = {};
    for (const command of ["set", "del", "sadd", "pexpire", "srem"]) {
      tx[command] = (...args: unknown[]) => {
        queued.push([command, ...args]);
        return tx;
      };
    }
    tx["exec"] = () => Promise.resolve(replies);
    const client = { multi: () => tx } as unknown as Valkey;
    return { kv: new ValkeyKv(client), queued };
  }

  it("queues every op in one MULTI and maps the replies back to the ops", async () => {
    const { kv, queued } = fakeTx([
      [null, "OK"],
      [null, null],
      [null, 1],
      [null, 1],
      [null, 1],
      [null, 0],
    ]);
    const results = await kv.multi([
      { op: "set", key: "a", value: "1", ttlMs: 10.7 },
      { op: "set", key: "b", value: "2", ttlMs: 10 },
      { op: "del", key: "c" },
      { op: "sadd", key: "s", member: "m", ttlMs: 99 },
      { op: "srem", key: "s", member: "m" },
    ]);
    expect(results).toEqual([true, false, 1, 1, 0]);
    expect(queued).toEqual([
      ["set", "a", "1", "PX", 10],
      ["set", "b", "2", "PX", 10],
      ["del", "c"],
      ["sadd", "s", "m"],
      ["pexpire", "s", 99],
      ["srem", "s", "m"],
    ]);
  });

  it("rejects when EXEC was aborted or any command failed", async () => {
    await expect(
      fakeTx(null).kv.multi([{ op: "del", key: "k" }]),
    ).rejects.toThrow("MULTI aborted");
    await expect(
      fakeTx([[new Error("OOM"), undefined]]).kv.multi([
        { op: "del", key: "k" },
      ]),
    ).rejects.toThrow("OOM");
  });
});
