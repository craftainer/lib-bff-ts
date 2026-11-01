import { Valkey } from "iovalkey";

/** One operation of an atomic {@link KvClient.multi}. Every key written has a TTL. */
export type KvOp =
  | {
      op: "set";
      key: string;
      value: string;
      ttlMs: number;
    }
  | { op: "del"; key: string }
  /** Adds a member to a set and (re)sets the set's TTL. */
  | { op: "sadd"; key: string; member: string; ttlMs: number }
  | { op: "srem"; key: string; member: string };

/**
 * The minimal key-value surface the session store needs. Every key has a
 * TTL. The Valkey implementation wraps `iovalkey`; the in-memory one backs
 * tests, so the store logic is exercised without a server.
 */
export interface KvClient {
  get(key: string): Promise<string | null>;
  /**
   * Returns false only when `nx` is set and the key already exists.
   */
  set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean>;
  /** Atomically reads and deletes a key. */
  getDel(key: string): Promise<string | null>;
  /** Returns the number of keys that existed. */
  del(...keys: string[]): Promise<number>;
  /** Returns false when the key does not exist. */
  pexpire(key: string, ttlMs: number): Promise<boolean>;
  smembers(key: string): Promise<string[]>;
  /**
   * Applies the ops as one unit of isolation (Valkey `MULTI`/`EXEC`; in
   * memory, one synchronous tick): no other command runs in between. It is
   * NOT a rollback: Valkey does not undo ops that fail at run time (for
   * example `WRONGTYPE`), so a rejection can leave earlier ops applied and
   * callers must clean up. Returns one result per op: `set` a boolean,
   * `del`, `sadd` and `srem` a count. Rejects when any op fails.
   */
  multi(ops: KvOp[]): Promise<unknown[]>;
  /**
   * Compare-and-set: overwrites `key` with `value` (JSON, with the new
   * version already inside) only when the JSON stored at `key` has
   * `version === expectedVersion`. False when the key is missing or the
   * version differs. Atomic (a Lua script in Valkey).
   */
  compareAndSetVersion(
    key: string,
    expectedVersion: number,
    value: string,
    ttlMs: number,
  ): Promise<boolean>;
  /** Deletes the key only when it still holds `value` (lock release). Returns whether it deleted. */
  delIfEquals(key: string, value: string): Promise<boolean>;
  ping(): Promise<void>;
  quit(): Promise<void>;
}

interface Entry {
  value: string | undefined;
  members: Set<string> | undefined;
  expiresAt: number | undefined;
}

function versionOf(json: string): unknown {
  try {
    return (JSON.parse(json) as { version?: unknown }).version;
  } catch {
    return undefined;
  }
}

/** In-memory {@link KvClient} for tests and single-process use. Not shared between replicas. */
export class MemoryKv implements KvClient {
  readonly #entries = new Map<string, Entry>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  #live(key: string): Entry | undefined {
    const entry = this.#entries.get(key);
    if (entry?.expiresAt !== undefined && entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry;
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#live(key)?.value ?? null);
  }

  #set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): boolean {
    const exists = this.#live(key) !== undefined;
    if (opts.nx === true && exists) {
      return false;
    }
    this.#entries.set(key, {
      value,
      members: undefined,
      expiresAt: this.#now() + opts.ttlMs,
    });
    return true;
  }

  #del(key: string): number {
    const existed = this.#live(key) !== undefined;
    this.#entries.delete(key);
    return existed ? 1 : 0;
  }

  set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean> {
    return Promise.resolve(this.#set(key, value, opts));
  }

  async getDel(key: string): Promise<string | null> {
    const value = await this.get(key);
    this.#entries.delete(key);
    return value;
  }

  del(...keys: string[]): Promise<number> {
    return Promise.resolve(
      keys.reduce((count, key) => count + this.#del(key), 0),
    );
  }

  pexpire(key: string, ttlMs: number): Promise<boolean> {
    const entry = this.#live(key);
    if (entry === undefined) {
      return Promise.resolve(false);
    }
    entry.expiresAt = this.#now() + ttlMs;
    return Promise.resolve(true);
  }

  compareAndSetVersion(
    key: string,
    expectedVersion: number,
    value: string,
    ttlMs: number,
  ): Promise<boolean> {
    const current = this.#live(key)?.value;
    if (current === undefined || versionOf(current) !== expectedVersion) {
      return Promise.resolve(false);
    }
    return Promise.resolve(this.#set(key, value, { ttlMs }));
  }

  multi(ops: KvOp[]): Promise<unknown[]> {
    // No await between the ops: nothing else runs in the middle.
    return Promise.resolve(
      ops.map((op): unknown => {
        switch (op.op) {
          case "set":
            return this.#set(op.key, op.value, op);
          case "del":
            return this.#del(op.key);
          case "sadd": {
            const existing = this.#live(op.key);
            const members = existing?.members ?? new Set<string>();
            const added = members.has(op.member) ? 0 : 1;
            members.add(op.member);
            this.#entries.set(op.key, {
              value: undefined,
              members,
              expiresAt: this.#now() + op.ttlMs,
            });
            return added;
          }
          case "srem":
            return this.#live(op.key)?.members?.delete(op.member) === true
              ? 1
              : 0;
        }
      }),
    );
  }

  smembers(key: string): Promise<string[]> {
    return Promise.resolve([...(this.#live(key)?.members ?? [])]);
  }

  async delIfEquals(key: string, value: string): Promise<boolean> {
    if ((await this.get(key)) !== value) {
      return false;
    }
    this.#entries.delete(key);
    return true;
  }

  ping(): Promise<void> {
    return Promise.resolve();
  }

  quit(): Promise<void> {
    return Promise.resolve();
  }
}

const CAS_VERSION_SCRIPT = `
local current = redis.call("get", KEYS[1])
if not current then return 0 end
local ok, decoded = pcall(cjson.decode, current)
if not ok or type(decoded) ~= "table" or decoded.version ~= tonumber(ARGV[1]) then return 0 end
redis.call("set", KEYS[1], ARGV[2], "PX", ARGV[3])
return 1`;

const RELEASE_LOCK_SCRIPT =
  'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end';

/** {@link KvClient} over an `iovalkey` connection. */
export class ValkeyKv implements KvClient {
  readonly #client: Valkey;

  constructor(client: Valkey) {
    this.#client = client;
  }

  get(key: string): Promise<string | null> {
    return this.#client.get(key);
  }

  async set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean> {
    const px = Math.max(1, Math.floor(opts.ttlMs));
    let reply: "OK" | null;
    if (opts.nx === true) {
      reply = await this.#client.set(key, value, "PX", px, "NX");
    } else {
      reply = await this.#client.set(key, value, "PX", px);
    }
    return reply === "OK";
  }

  getDel(key: string): Promise<string | null> {
    return this.#client.getdel(key);
  }

  del(...keys: string[]): Promise<number> {
    return this.#client.del(...keys);
  }

  async pexpire(key: string, ttlMs: number): Promise<boolean> {
    return (await this.#client.pexpire(key, ttlMs)) === 1;
  }

  async multi(ops: KvOp[]): Promise<unknown[]> {
    const tx = this.#client.multi();
    // Index of each op's first command in the EXEC reply (sadd queues two).
    const first: number[] = [];
    let queued = 0;
    for (const op of ops) {
      first.push(queued);
      switch (op.op) {
        case "set": {
          const px = Math.max(1, Math.floor(op.ttlMs));
          tx.set(op.key, op.value, "PX", px);
          queued += 1;
          break;
        }
        case "del":
          tx.del(op.key);
          queued += 1;
          break;
        case "sadd":
          tx.sadd(op.key, op.member);
          tx.pexpire(op.key, Math.max(1, Math.floor(op.ttlMs)));
          queued += 2;
          break;
        case "srem":
          tx.srem(op.key, op.member);
          queued += 1;
          break;
      }
    }
    const replies = await tx.exec();
    if (replies === null) {
      throw new Error("MULTI aborted");
    }
    for (const [error] of replies) {
      if (error !== null) {
        throw error;
      }
    }
    return ops.map((op, i) => {
      const reply = (replies[first[i] as number] as [unknown, unknown])[1];
      return op.op === "set" ? reply === "OK" : reply;
    });
  }

  smembers(key: string): Promise<string[]> {
    return this.#client.smembers(key);
  }

  async compareAndSetVersion(
    key: string,
    expectedVersion: number,
    value: string,
    ttlMs: number,
  ): Promise<boolean> {
    const reply = await this.#client.eval(
      CAS_VERSION_SCRIPT,
      1,
      key,
      expectedVersion,
      value,
      Math.max(1, Math.floor(ttlMs)),
    );
    return reply === 1;
  }

  async delIfEquals(key: string, value: string): Promise<boolean> {
    return (await this.#client.eval(RELEASE_LOCK_SCRIPT, 1, key, value)) === 1;
  }

  async ping(): Promise<void> {
    await this.#client.ping();
  }

  async quit(): Promise<void> {
    if (this.#client.status === "ready") {
      await this.#client.quit();
    } else {
      this.#client.disconnect();
    }
  }
}

/**
 * Builds a lazily connecting Valkey client from a `redis(s)://` or
 * `valkey(s)://` URL. Nothing connects until the first command.
 */
export function createValkeyKv(url: string): KvClient {
  return new ValkeyKv(
    new Valkey(url.replace(/^valkey(s?):/, "redis$1:"), {
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      enableReadyCheck: true,
    }),
  );
}
