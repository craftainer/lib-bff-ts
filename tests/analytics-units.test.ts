import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from "vitest";
import {
  BATCH_SIZE,
  createLogAdapter,
  createOtelAdapter,
  createUmamiAdapter,
  flatten,
  noneAdapter,
  umamiItem,
  USER_AGENT,
} from "../src/analytics/adapters.ts";
import { BoundedQueue } from "../src/analytics/queue.ts";
import type { AnalyticsEvent } from "../src/analytics/types.ts";
import { bodySchema } from "../src/analytics/validate.ts";
import { createVisitorToken } from "../src/analytics/visitor.ts";

const event = (overrides: Partial<AnalyticsEvent> = {}): AnalyticsEvent => ({
  name: "hero.created",
  props: {},
  url: "/heroes",
  timestamp: 1_700_000_000,
  visitor: "tok",
  ...overrides,
});

type Warn = (...args: unknown[]) => void;
const fakeLog = (): { warn: Mock<Warn> } => ({ warn: vi.fn<Warn>() });

describe("visitor token", () => {
  const DAY = Date.UTC(2026, 9, 31, 12);
  const salts = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];

  it("is 22 base64url characters and stable within a UTC day", () => {
    let now = DAY;
    const random = vi.fn(() => salts[random.mock.calls.length - 1] as Buffer);
    const token = createVisitorToken(() => now, random);
    const first = token("203.0.113.7", "Mozilla/5.0");
    expect(first).toMatch(/^[A-Za-z0-9_-]{22}$/);
    now = Date.UTC(2026, 9, 31, 23, 59, 59);
    expect(token("203.0.113.7", "Mozilla/5.0")).toBe(first);
    expect(random).toHaveBeenCalledTimes(1);
  });

  it("depends on both the IP and the User-Agent", () => {
    const token = createVisitorToken(
      () => DAY,
      () => salts[0] as Buffer,
    );
    const base = token("203.0.113.7", "A");
    expect(token("203.0.113.8", "A")).not.toBe(base);
    expect(token("203.0.113.7", "B")).not.toBe(base);
    expect(token("203.0.113.7", undefined)).toBe(token("203.0.113.7", ""));
    // The separator keeps ("ab", "c") apart from ("a", "bc").
    expect(token("ab", "c")).not.toBe(token("a", "bc"));
  });

  it("changes when the UTC date changes (new salt)", () => {
    let now = DAY;
    const random = vi.fn(() => salts[random.mock.calls.length - 1] as Buffer);
    const token = createVisitorToken(() => now, random);
    const today = token("203.0.113.7", "A");
    now = Date.UTC(2026, 10, 1, 0, 0, 0);
    expect(token("203.0.113.7", "A")).not.toBe(today);
    expect(random).toHaveBeenCalledTimes(2);
  });

  it("uses 32 random bytes by default", () => {
    const a = createVisitorToken()("1.2.3.4", "ua");
    expect(createVisitorToken()("1.2.3.4", "ua")).not.toBe(a);
  });
});

describe("BoundedQueue", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("flushes every interval and not before", async () => {
    const deliver = vi.fn(() => Promise.resolve());
    const queue = new BoundedQueue<number>({
      capacity: 10,
      intervalMs: 5000,
      deliver,
      log: fakeLog(),
    });
    queue.push(1);
    queue.push(2);
    await vi.advanceTimersByTimeAsync(4999);
    expect(deliver).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(deliver).toHaveBeenCalledExactlyOnceWith([1, 2]);
    await vi.advanceTimersByTimeAsync(5000);
    expect(deliver).toHaveBeenCalledTimes(1);
    await queue.close();
  });

  it("drops on overflow and logs the count once per flush window", async () => {
    const log = fakeLog();
    const deliver = vi.fn(() => Promise.resolve());
    const queue = new BoundedQueue<number>({
      capacity: 2,
      intervalMs: 5000,
      deliver,
      log,
    });
    for (const n of [1, 2, 3, 4, 5]) {
      queue.push(n);
    }
    expect(log.warn).not.toHaveBeenCalled();
    await queue.flush();
    expect(deliver).toHaveBeenCalledExactlyOnceWith([1, 2]);
    expect(log.warn).toHaveBeenCalledExactlyOnceWith(
      { dropped: 3 },
      "analytics queue full: events dropped",
    );
    await queue.flush();
    expect(log.warn).toHaveBeenCalledTimes(1);
    await queue.close();
  });

  it("logs a failing delivery and keeps going", async () => {
    const log = fakeLog();
    const deliver = vi
      .fn<(items: number[]) => Promise<void>>()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValue(undefined);
    const queue = new BoundedQueue<number>({
      capacity: 5,
      intervalMs: 5000,
      deliver,
      log,
    });
    queue.push(1);
    await queue.flush();
    expect(log.warn).toHaveBeenCalledExactlyOnceWith(
      { err: "Error: boom", events: 1 },
      "analytics delivery failed",
    );
    queue.push(2);
    await queue.flush();
    expect(deliver).toHaveBeenLastCalledWith([2]);
    await queue.close();
  });

  it("survives a logger that throws", async () => {
    const log = fakeLog();
    log.warn.mockImplementation(() => {
      throw new Error("transport down");
    });
    const queue = new BoundedQueue<number>({
      capacity: 1,
      intervalMs: 5000,
      deliver: () => Promise.reject(new Error("boom")),
      log,
    });
    queue.push(1);
    queue.push(2);
    await expect(queue.flush()).resolves.toBeUndefined();
    queue.push(3);
    await expect(queue.close()).resolves.toBeUndefined();
  });

  it("close flushes the rest, stops the timer and ignores later pushes", async () => {
    const deliver = vi.fn(() => Promise.resolve());
    const queue = new BoundedQueue<number>({
      capacity: 5,
      intervalMs: 5000,
      deliver,
      log: fakeLog(),
    });
    queue.push(1);
    await queue.close();
    expect(deliver).toHaveBeenCalledExactlyOnceWith([1]);
    queue.push(2);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(deliver).toHaveBeenCalledTimes(1);
  });

  it("close without any push is a no-op", async () => {
    const deliver = vi.fn(() => Promise.resolve());
    const queue = new BoundedQueue<number>({
      capacity: 5,
      intervalMs: 5000,
      deliver,
      log: fakeLog(),
    });
    await queue.close();
    expect(deliver).not.toHaveBeenCalled();
  });
});

describe("adapters", () => {
  it("none discards", async () => {
    await expect(noneAdapter.send([event()])).resolves.toBeUndefined();
  });

  it("flatten gives primitive analytics_prop_<key> fields", () => {
    expect(flatten(event({ props: { plan: "free", n: 3, ok: true } }))).toEqual(
      {
        analytics_event: "hero.created",
        analytics_url: "/heroes",
        analytics_prop_plan: "free",
        analytics_prop_n: 3,
        analytics_prop_ok: true,
      },
    );
  });

  it("log writes one line per event without the visitor token", async () => {
    const info = vi.fn();
    await createLogAdapter({ info } as never).send([
      event({ props: { plan: "free" } }),
      event({ name: "hero.deleted" }),
    ]);
    expect(info).toHaveBeenCalledTimes(2);
    expect(info).toHaveBeenNthCalledWith(
      1,
      {
        analytics_event: "hero.created",
        analytics_url: "/heroes",
        analytics_prop_plan: "free",
      },
      "analytics_event",
    );
  });

  it("umami item omits hostname and data when empty", () => {
    expect(umamiItem(event(), "site", null)).toEqual({
      type: "event",
      payload: {
        website: "site",
        url: "/heroes",
        name: "hero.created",
        ip: "tok",
        timestamp: 1_700_000_000,
      },
    });
  });
});

describe("otel adapter without the optional peer", () => {
  it("warns once and falls back to none", async () => {
    const log = fakeLog();
    const adapter = await createOtelAdapter(log, () =>
      Promise.reject(new Error("Cannot find package")),
    );
    expect(adapter).toBe(noneAdapter);
    expect(log.warn).toHaveBeenCalledTimes(1);
  });
});

describe("umami adapter over a fetch stub", () => {
  const make = (
    fetchStub: typeof fetch,
    log = fakeLog(),
    endpoint = "http://umami.test///",
  ): ReturnType<typeof createUmamiAdapter> =>
    createUmamiAdapter({
      endpoint,
      siteId: "site",
      hostname: "app.example",
      log,
      fetch: fetchStub,
    });

  it("trims the endpoint, sends the bot-safe User-Agent and manual redirects", async () => {
    const stub = vi.fn(() =>
      Promise.resolve(new Response('{"errors":0}', { status: 200 })),
    );
    await make(stub as never).send([event()]);
    const [url, init] = stub.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://umami.test/api/batch");
    expect(init.redirect).toBe("manual");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      "content-type": "application/json",
      "user-agent": USER_AGENT,
    });
  });

  it("splits at BATCH_SIZE", async () => {
    const sizes: number[] = [];
    const stub = vi.fn((_url: string, init: RequestInit) => {
      sizes.push((JSON.parse(init.body as string) as unknown[]).length);
      return Promise.resolve(new Response("{}", { status: 200 }));
    });
    const events = Array.from({ length: 2 * BATCH_SIZE + 1 }, () => event());
    await make(stub as never).send(events);
    expect(sizes).toEqual([50, 50, 1]);
  });

  it("logs non-200 replies, non-JSON bodies and error counts", async () => {
    const log = fakeLog();
    const replies = [
      new Response("", { status: 500 }),
      new Response("<html>", { status: 200 }),
      new Response("null", { status: 200 }),
      new Response('{"errors":2}', { status: 200 }),
    ];
    const stub = vi.fn(() => Promise.resolve(replies.shift() as Response));
    const adapter = make(stub as never, log);
    for (let i = 0; i < 4; i += 1) {
      await adapter.send([event()]);
    }
    expect(log.warn.mock.calls).toEqual([
      [{ status: 500 }, "umami batch rejected"],
      ["umami batch reply was not JSON"],
      [{ errors: 2, events: 1 }, "umami batch reported errors"],
    ]);
  });

  it("logs a redirect without following it", async () => {
    const log = fakeLog();
    const replies = [
      new Response("", { status: 301, headers: { location: "/elsewhere" } }),
      new Response("", { status: 302 }),
    ];
    const stub = vi.fn(() => Promise.resolve(replies.shift() as Response));
    const adapter = make(stub as never, log);
    await adapter.send([event()]);
    await adapter.send([event()]);
    expect(stub).toHaveBeenCalledTimes(2);
    expect(log.warn.mock.calls).toEqual([
      [
        { status: 301, location: "/elsewhere" },
        "umami batch dropped: redirect; ANALYTICS_ENDPOINT must be the final URL",
      ],
      [
        { status: 302, location: "" },
        "umami batch dropped: redirect; ANALYTICS_ENDPOINT must be the final URL",
      ],
    ]);
  });

  it("logs a failed request and still sends the next chunk", async () => {
    const log = fakeLog();
    const stub = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValue(new Response("{}", { status: 200 }));
    await make(stub as never, log).send(
      Array.from({ length: BATCH_SIZE + 1 }, () => event()),
    );
    expect(stub).toHaveBeenCalledTimes(2);
    expect(log.warn).toHaveBeenCalledExactlyOnceWith(
      { err: "TypeError: fetch failed" },
      "umami batch failed",
    );
  });

  it("times out", async () => {
    const server = createServer(() => {
      // Never answers.
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const log = fakeLog();
    const adapter = createUmamiAdapter({
      endpoint: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      siteId: "site",
      hostname: null,
      log,
      timeoutMs: 50,
    });
    try {
      await adapter.send([event()]);
    } finally {
      server.closeAllConnections();
      server.close();
    }
    expect(log.warn).toHaveBeenCalledTimes(1);
    const [fields] = log.warn.mock.calls[0] as [{ err: string }];
    expect(fields.err).toMatch(/TimeoutError/);
  });

  it("uses the global fetch and 2 s timeout by default", async () => {
    const adapter = createUmamiAdapter({
      endpoint: "http://127.0.0.1:1",
      siteId: "site",
      hostname: null,
      log: fakeLog(),
    });
    await expect(adapter.send([event()])).resolves.toBeUndefined();
  });
});

describe("validation schema", () => {
  const schema = bodySchema(["plan", "n"]);

  it("normalises one event and an array alike", () => {
    expect(schema.parse({ name: "a.b" })).toEqual([
      { name: "a.b", props: {}, url: "/" },
    ]);
    expect(schema.parse([{ name: "a.b", url: "/x?y#z" }])).toEqual([
      { name: "a.b", props: {}, url: "/x" },
    ]);
  });

  it.each([
    ["no dot", { name: "pageview" }],
    ["uppercase", { name: "Hero.created" }],
    ["trailing dot", { name: "hero." }],
    ["digit start", { name: "1a.b" }],
    ["51 chars", { name: `a.${"b".repeat(49)}` }],
    ["not a string", { name: 3 }],
    ["unknown field", { name: "a.b", extra: 1 }],
    ["prop not allowlisted", { name: "a.b", props: { secret: "x" } }],
    ["prop is an object", { name: "a.b", props: { plan: { a: 1 } } }],
    ["prop is null", { name: "a.b", props: { plan: null } }],
    ["prop is an array", { name: "a.b", props: { plan: [1] } }],
    ["prop over 200 chars", { name: "a.b", props: { plan: "x".repeat(201) } }],
    ["props is an array", { name: "a.b", props: [] }],
    ["url is absolute", { name: "a.b", url: "https://evil.test/x" }],
    ["url is protocol-relative", { name: "a.b", url: "//evil.test/x" }],
    ["url is relative", { name: "a.b", url: "x" }],
    ["url has a newline", { name: "a.b", url: "/x\ny" }],
    ["url has a DEL", { name: "a.b", url: "/x\u007f" }],
    ["url over 500 chars", { name: "a.b", url: `/${"x".repeat(500)}` }],
    ["empty array", []],
    ["51 events", Array.from({ length: 51 }, () => ({ name: "a.b" }))],
    ["null", null],
    ["a string", "a.b"],
  ])("rejects %s", (_label, body) => {
    expect(schema.safeParse(body).success).toBe(false);
  });

  it("accepts the boundaries", () => {
    const fifty = Array.from({ length: 50 }, () => ({ name: "a.b" }));
    expect(schema.parse(fifty)).toHaveLength(50);
    const name = `a.${"b".repeat(48)}`;
    expect(name).toHaveLength(50);
    expect(
      schema.parse({
        name,
        props: { plan: "x".repeat(200), n: 2.5 },
        url: `/${"x".repeat(499)}`,
      }),
    ).toHaveLength(1);
  });

  it("rejects every prop when the allowlist is empty", () => {
    expect(
      bodySchema([]).safeParse({ name: "a.b", props: { plan: "x" } }).success,
    ).toBe(false);
    expect(bodySchema([]).safeParse({ name: "a.b", props: {} }).success).toBe(
      true,
    );
  });
});
