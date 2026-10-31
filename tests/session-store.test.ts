import { describe, expect, it } from "vitest";
import { KvSessionStore, MemoryKv, type KvClient } from "../src/session.ts";
import {
  createMemorySessionStore,
  randomId,
  type SessionData,
} from "../src/auth/store.ts";

function data(over: Partial<SessionData> = {}): SessionData {
  return {
    sub: "alice",
    sid: "sid-1",
    name: "Alice",
    email: "alice@example.com",
    roles: { realm: ["user"] },
    idToken: "id",
    accessToken: "at",
    refreshToken: "rt",
    accessExpiresAt: 100,
    createdAt: 1,
    absoluteExpiresAt: 1000,
    version: 0,
    ...over,
  };
}

function setup(): {
  store: KvSessionStore;
  kv: MemoryKv;
  clock: { now: number };
} {
  const clock = { now: 1_000_000 };
  const kv = new MemoryKv(() => clock.now);
  return {
    store: new KvSessionStore(kv, { indexTtlSeconds: 3600 }),
    kv,
    clock,
  };
}

describe("randomId", () => {
  it("is at least 128 bits (256 here), URL-safe and unique", () => {
    const a = randomId();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomId()).not.toBe(a);
  });
});

describe("KvSessionStore", () => {
  it("stores and reads sessions until their TTL runs out", async () => {
    const { store, clock } = setup();
    await store.put("s1", data(), 60);
    expect(await store.get("s1")).toEqual(data());
    clock.now += 59_000;
    expect(await store.get("s1")).toBeDefined();
    clock.now += 2_000;
    expect(await store.get("s1")).toBeUndefined();
    expect(await store.get("never")).toBeUndefined();
  });

  it("slides the idle timeout with touch, and reports missing sessions", async () => {
    const { store, clock } = setup();
    await store.put("s1", data(), 60);
    clock.now += 50_000;
    expect(await store.touch("s1", 60)).toBe(true);
    clock.now += 50_000;
    expect(await store.get("s1")).toBeDefined();
    expect(await store.touch("nope", 60)).toBe(false);
  });

  it("replace is a compare-and-set on the version: it bumps it, and refuses a stale or vanished session", async () => {
    const { store, kv } = setup();
    await store.put("s1", data(), 60);
    expect(
      await store.replace("s1", data({ accessToken: "new" }), 60_000, 0),
    ).toBe(true);
    const stored = await store.get("s1");
    expect(stored?.accessToken).toBe("new");
    expect(stored?.version).toBe(1);
    // A second writer that started from version 0 lost the race.
    expect(
      await store.replace("s1", data({ accessToken: "late" }), 60_000, 0),
    ).toBe(false);
    expect((await store.get("s1"))?.accessToken).toBe("new");
    expect(
      await store.replace("s1", data({ accessToken: "next" }), 60_000, 1),
    ).toBe(true);
    expect((await store.get("s1"))?.version).toBe(2);
    await store.destroy("s1");
    expect(await store.replace("s1", data(), 60_000, 2)).toBe(false);
    expect(await kv.get("sess:s1")).toBeNull();
  });

  it("take returns exactly what was stored when it removed the session", async () => {
    const { store, kv } = setup();
    await store.put("s1", data(), 60);
    await store.replace("s1", data({ refreshToken: "rotated" }), 60_000, 0);
    const taken = await store.take("s1");
    expect(taken?.refreshToken).toBe("rotated");
    expect(taken?.version).toBe(1);
    expect(await store.take("s1")).toBeUndefined();
    expect(await kv.smembers("sub:alice")).toEqual([]);
    expect(await kv.smembers("sid:sid-1")).toEqual([]);
  });

  it("treats corrupt or malformed entries as missing", async () => {
    const { store, kv } = setup();
    await kv.set("sess:bad-json", "{not json", { ttlMs: 1000 });
    await kv.set("sess:bad-shape", JSON.stringify({ sub: 1 }), { ttlMs: 1000 });
    expect(await store.get("bad-json")).toBeUndefined();
    expect(await store.get("bad-shape")).toBeUndefined();
  });

  it("destroys a session and removes it from the indexes", async () => {
    const { store, kv } = setup();
    await store.put("s1", data(), 60);
    await store.put("s2", data({ sid: null }), 60);
    expect(await store.destroy("s1")).toBe(true);
    expect(await store.destroy("s1")).toBe(false);
    expect(await kv.smembers("sid:sid-1")).toEqual([]);
    expect(await kv.smembers("sub:alice")).toEqual(["s2"]);
    expect(await store.destroy("s2")).toBe(true);
    expect(await kv.smembers("sub:alice")).toEqual([]);
  });

  it("destroys all sessions of a sid or a sub and counts only live ones", async () => {
    const { store, clock } = setup();
    await store.put("a1", data({ sid: "x" }), 60);
    await store.put("a2", data({ sid: "y" }), 60);
    await store.put("a3", data({ sid: "y" }), 5);
    await store.put("b1", data({ sub: "bob", sid: "z" }), 60);
    clock.now += 10_000;
    expect(await store.destroyBySid("y")).toBe(1);
    expect(await store.get("a2")).toBeUndefined();
    expect(await store.get("a1")).toBeDefined();
    expect(await store.destroyBySub("alice")).toBe(1);
    expect(await store.get("b1")).toBeDefined();
    expect(await store.destroyBySid("unknown")).toBe(0);
    expect(await store.destroyBySub("alice")).toBe(0);
  });

  it("keeps the indexes for as long as the longest session can live", async () => {
    const { store, kv, clock } = setup();
    await store.put("s1", data(), 60);
    clock.now += 3_599_000;
    expect(await kv.smembers("sub:alice")).toEqual(["s1"]);
    clock.now += 2_000;
    expect(await kv.smembers("sub:alice")).toEqual([]);
  });

  it("grants the refresh lock to one holder at a time, released only by its owner", async () => {
    const { store, clock } = setup();
    const token = await store.acquireLock("s1", 1000);
    expect(token).toBeDefined();
    expect(await store.acquireLock("s1", 1000)).toBeUndefined();
    await store.releaseLock("s1", "someone-else");
    expect(await store.acquireLock("s1", 1000)).toBeUndefined();
    await store.releaseLock("s1", token as string);
    const next = await store.acquireLock("s1", 1000);
    expect(next).toBeDefined();
    clock.now += 1500;
    expect(await store.acquireLock("s1", 1000)).toBeDefined();
  });

  it("keeps login transactions single-use and short-lived", async () => {
    const { store, clock } = setup();
    const tx = { nonce: "n", codeVerifier: "v", returnTo: "/" };
    await store.putTransaction("st", tx, 300);
    expect(await store.takeTransaction("st")).toEqual(tx);
    expect(await store.takeTransaction("st")).toBeUndefined();
    await store.putTransaction("st2", tx, 300);
    clock.now += 301_000;
    expect(await store.takeTransaction("st2")).toBeUndefined();
    expect(await store.takeTransaction("missing")).toBeUndefined();
  });

  it("claims a key once within its TTL", async () => {
    const { store, clock } = setup();
    expect(await store.claimOnce("jti:1", 60)).toBe(true);
    expect(await store.claimOnce("jti:1", 60)).toBe(false);
    clock.now += 61_000;
    expect(await store.claimOnce("jti:1", 60)).toBe(true);
  });

  it("gives up a claim so the claimed work can be retried", async () => {
    const { store } = setup();
    expect(await store.claimOnce("jti:2", 60)).toBe(true);
    await store.releaseClaim("jti:2");
    expect(await store.claimOnce("jti:2", 60)).toBe(true);
  });

  it("keeps a session that logs in during a back-channel logout reachable through its index", async () => {
    const { store, kv } = setup();
    await store.put("old", data(), 60);
    // A login lands between the logout's read of the index and its end: simulate
    // it by adding the new session as the first destroy runs.
    const realDestroy = store.destroy.bind(store);
    store.destroy = async (id: string): Promise<boolean> => {
      await store.put("new", data(), 60);
      return realDestroy(id);
    };
    expect(await store.destroyBySub("alice")).toBe(1);
    expect(await kv.smembers("sub:alice")).toEqual(["new"]);
    expect(await kv.smembers("sid:sid-1")).toEqual(["new"]);
    store.destroy = realDestroy;
    expect(await store.destroyBySid("sid-1")).toBe(1);
  });

  it("finds every session of a sid or sub for back-channel logout", async () => {
    const { store } = setup();
    for (const id of ["a", "b", "c"]) {
      await store.put(id, data(), 60);
    }
    expect(await store.destroyBySid("sid-1")).toBe(3);
    await store.put("d", data({ sid: null }), 60);
    expect(await store.destroyBySub("alice")).toBe(1);
  });

  it("pings and closes", async () => {
    const { store } = setup();
    await expect(store.ping()).resolves.toBeUndefined();
    await expect(store.close()).resolves.toBeUndefined();
  });

  it("builds an in-memory store with defaults", async () => {
    const store = createMemorySessionStore();
    await store.put("s", data(), 60);
    expect(await store.get("s")).toBeDefined();
  });
});

describe("MemoryKv", () => {
  it("implements the KvClient contract", async () => {
    let now = 0;
    const kv: KvClient = new MemoryKv(() => now);
    expect(await kv.set("k", "v", { ttlMs: 10, nx: true })).toBe(true);
    expect(await kv.set("k", "w", { ttlMs: 10, nx: true })).toBe(false);
    expect(await kv.set("k", "w", { ttlMs: 10 })).toBe(true);
    expect(await kv.get("k")).toBe("w");
    expect(await kv.pexpire("k", 100)).toBe(true);
    expect(await kv.pexpire("nope", 100)).toBe(false);
    expect(await kv.getDel("k")).toBe("w");
    expect(await kv.getDel("k")).toBeNull();
    await kv.set("a", "1", { ttlMs: 10 });
    await kv.set("b", "1", { ttlMs: 10 });
    now = 11;
    await kv.set("c", "1", { ttlMs: 10 });
    expect(await kv.del("a", "b", "c", "d")).toBe(1);
    expect(await kv.delIfEquals("x", "1")).toBe(false);
    await kv.set("x", "1", { ttlMs: 10 });
    expect(await kv.delIfEquals("x", "2")).toBe(false);
    expect(await kv.delIfEquals("x", "1")).toBe(true);
    expect(
      await kv.multi([
        { op: "sadd", key: "set", member: "m1", ttlMs: 50 },
        { op: "sadd", key: "set", member: "m1", ttlMs: 50 },
        { op: "sadd", key: "set", member: "m2", ttlMs: 50 },
        { op: "srem", key: "set", member: "m1" },
        { op: "srem", key: "set", member: "nope" },
        { op: "srem", key: "missing", member: "m1" },
        { op: "set", key: "s", value: "1", ttlMs: 50 },
        { op: "del", key: "s" },
        { op: "del", key: "s" },
      ]),
    ).toEqual([1, 0, 1, 1, 0, 0, true, 1, 0]);
    expect(await kv.smembers("set")).toEqual(["m2"]);
    now += 51;
    expect(await kv.smembers("set")).toEqual([]);
    expect(await kv.smembers("missing")).toEqual([]);
    await kv.set("v", JSON.stringify({ version: 3 }), { ttlMs: 100 });
    expect(await kv.compareAndSetVersion("v", 2, '{"version":3}', 100)).toBe(
      false,
    );
    expect(await kv.compareAndSetVersion("v", 3, '{"version":4}', 100)).toBe(
      true,
    );
    expect(await kv.get("v")).toBe('{"version":4}');
    expect(await kv.compareAndSetVersion("nope", 0, "{}", 100)).toBe(false);
    await kv.set("junk", "not json", { ttlMs: 100 });
    expect(await kv.compareAndSetVersion("junk", 0, "{}", 100)).toBe(false);
    await expect(kv.ping()).resolves.toBeUndefined();
    await expect(kv.quit()).resolves.toBeUndefined();
  });
});

describe("session writes", () => {
  it("put cleans up its session key when the transaction fails part-way", async () => {
    const kv = new MemoryKv();
    const realMulti = kv.multi.bind(kv);
    // Valkey does not roll back: the ops were applied, then EXEC reported a failure.
    kv.multi = async (ops) => {
      await realMulti(ops);
      throw new Error("WRONGTYPE on a later op");
    };
    const store = new KvSessionStore(kv, { indexTtlSeconds: 3600 });
    await expect(store.put("s1", data(), 60)).rejects.toThrow("WRONGTYPE");
    expect(await kv.get("sess:s1")).toBeNull();
  });

  it("put still reports the original failure when the cleanup fails too", async () => {
    const kv = new MemoryKv();
    kv.multi = () => Promise.reject(new Error("connection lost"));
    kv.del = () => Promise.reject(new Error("still down"));
    const store = new KvSessionStore(kv, { indexTtlSeconds: 3600 });
    await expect(store.put("s1", data(), 60)).rejects.toThrow(
      "connection lost",
    );
  });

  it("leaves a stale index member behind, harmlessly, when the index cleanup of take fails", async () => {
    const kv = new MemoryKv();
    await new KvSessionStore(kv, { indexTtlSeconds: 3600 }).put(
      "s1",
      data(),
      60,
    );
    const realMulti = kv.multi.bind(kv);
    kv.multi = () => Promise.reject(new Error("connection lost"));
    const store = new KvSessionStore(kv, { indexTtlSeconds: 3600 });
    await expect(store.take("s1")).rejects.toThrow("connection lost");
    expect(await kv.get("sess:s1")).toBeNull();
    expect(await kv.smembers("sub:alice")).toEqual(["s1"]);
    kv.multi = realMulti;
    expect(await store.destroyBySub("alice")).toBe(0);
    expect(await kv.smembers("sub:alice")).toEqual([]);
  });
});
