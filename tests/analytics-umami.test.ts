import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BATCH_SIZE, USER_AGENT } from "../src/analytics/adapters.ts";
import type { TestBff } from "./helpers/bff.ts";
import {
  makeAnalyticsBff,
  postEvents,
  startStubUmami,
  type StubUmami,
} from "./helpers/analytics.ts";

const SITE = "3f1c9c2e-6a52-5d7e-9a35-0a1b2c3d4e5f";

let stub: StubUmami;
let bff: TestBff | undefined;

beforeEach(async () => {
  stub = await startStubUmami();
});
afterEach(async () => {
  vi.useRealTimers();
  await bff?.app.close();
  bff = undefined;
  await stub.close();
});

async function start(env: Record<string, string> = {}): Promise<TestBff> {
  bff = await makeAnalyticsBff({
    ANALYTICS_BACKEND: "umami",
    ANALYTICS_ENDPOINT: stub.url,
    ANALYTICS_SITE_ID: SITE,
    ANALYTICS_HOSTNAME: "app.example.com",
    ANALYTICS_PROP_KEYS: "plan",
    BFF_TRUST_PROXY: "true",
    ...env,
  });
  return bff;
}

/** Closing the app flushes the queue. */
async function flush(): Promise<void> {
  await bff?.app.close();
}

const batches = (): { type: string; payload: Record<string, unknown> }[][] =>
  stub.requests.map((r) => JSON.parse(r.body) as never);

describe("Umami batch contract (stub of /api/batch, v3.4.1 schema)", () => {
  it("posts the exact documented body with a bot-safe User-Agent", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-31T12:00:00Z"));
    const b = await start();
    await postEvents(
      b,
      [
        { name: "hero.created", props: { plan: "free" }, url: "/heroes?x=1" },
        { name: "page.viewed" },
      ],
      { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0" },
      "203.0.113.7",
    );
    expect(stub.requests).toHaveLength(0); // queued, not yet flushed
    await flush();

    expect(stub.requests).toHaveLength(1);
    const req = stub.requests[0];
    expect(req?.method).toBe("POST");
    expect(req?.url).toBe("/api/batch");
    expect(req?.headers["user-agent"]).toBe(USER_AGENT);
    expect(req?.headers["user-agent"]).toBe(
      "Mozilla/5.0 (compatible; craftainer-bff)",
    );
    expect(req?.headers["content-type"]).toBe("application/json");
    const body = JSON.parse(req?.body ?? "") as {
      payload: { ip: string };
    }[];
    const ip = body[0]?.payload.ip;
    expect(ip).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(body).toEqual([
      {
        type: "event",
        payload: {
          website: SITE,
          url: "/heroes",
          name: "hero.created",
          ip,
          timestamp: 1_793_448_000,
          hostname: "app.example.com",
          data: { plan: "free" },
        },
      },
      {
        type: "event",
        payload: {
          website: SITE,
          url: "/",
          name: "page.viewed",
          ip,
          timestamp: 1_793_448_000,
          hostname: "app.example.com",
        },
      },
    ]);
    // No raw IP, no UA, no id, no title anywhere in the body.
    expect(req?.body).not.toMatch(/203\.0\.113\.7|Firefox|"id"|"title"/);
  });

  it("derives a stable daily token that differs per visitor and per day", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-31T23:00:00Z"));
    const b = await start();
    const send = (ip: string, ua: string): Promise<unknown> =>
      postEvents(b, { name: "a.b" }, { "user-agent": ua }, ip);
    await send("203.0.113.7", "UA-1");
    await send("203.0.113.7", "UA-1");
    await send("203.0.113.8", "UA-1");
    await send("203.0.113.7", "UA-2");
    vi.setSystemTime(new Date("2026-11-01T00:00:01Z"));
    await send("203.0.113.7", "UA-1");
    await flush();
    const ips = batches()
      .flat()
      .map((i) => i.payload["ip"]);
    expect(ips).toHaveLength(5);
    expect(ips[0]).toBe(ips[1]);
    expect(new Set(ips.slice(0, 4)).size).toBe(3);
    expect(ips[4]).not.toBe(ips[0]);
  });

  it("omits hostname when none is configured and tolerates a trailing slash", async () => {
    const b = await start({
      ANALYTICS_HOSTNAME: "",
      ANALYTICS_ENDPOINT: `${stub.url}/`,
    });
    await postEvents(b, { name: "a.b" });
    await flush();
    expect(stub.requests[0]?.url).toBe("/api/batch");
    expect(batches()[0]?.[0]?.payload).not.toHaveProperty("hostname");
  });

  it("splits more than 50 queued events into requests of at most 50", async () => {
    const b = await start();
    const events = (n: number): { name: string }[] =>
      Array.from({ length: n }, () => ({ name: "a.b" }));
    await postEvents(b, events(50));
    await postEvents(b, events(50));
    await postEvents(b, events(20));
    await flush();
    expect(batches().map((x) => x.length)).toEqual([
      BATCH_SIZE,
      BATCH_SIZE,
      20,
    ]);
  });

  it("drops events beyond the 1000-event queue and logs it once", async () => {
    const b = await start();
    const fifty = Array.from({ length: 50 }, () => ({ name: "a.b" }));
    for (let i = 0; i < 22; i += 1) {
      expect((await postEvents(b, fifty)).statusCode).toBe(202);
    }
    await flush();
    expect(batches().flat()).toHaveLength(1000);
    const overflow = b.logs.filter(
      (l) => l["msg"] === "analytics queue full: events dropped",
    );
    expect(overflow).toHaveLength(1);
    expect(overflow[0]).toMatchObject({ dropped: 100 });
  });

  it("flushes by timer every 5 seconds without a close", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const b = await start();
    await postEvents(b, { name: "a.b" });
    await vi.advanceTimersByTimeAsync(5000);
    // The flush runs real network I/O; give it time on the real clock.
    await vi.waitFor(() => expect(stub.requests).toHaveLength(1));
  });

  it("does not follow a redirect and logs the dropped batch", async () => {
    stub.reply = (req) =>
      req.url === "/api/batch"
        ? { status: 308, headers: { location: `${stub.url}/elsewhere` } }
        : { status: 200 };
    const b = await start();
    await postEvents(b, { name: "a.b" });
    await flush();
    expect(stub.requests.map((r) => r.url)).toEqual(["/api/batch"]);
    expect(
      b.logs.find((l) => String(l["msg"]).includes("redirect")),
    ).toMatchObject({ status: 308, level: 40 });
  });

  it("logs a 200 reply that reports errors, and a non-200 reply", async () => {
    stub.reply = () => ({
      status: 200,
      body: '{"size":1,"processed":0,"errors":1}',
    });
    const b = await start();
    await postEvents(b, { name: "a.b" });
    await flush();
    expect(
      b.logs.find((l) => l["msg"] === "umami batch reported errors"),
    ).toMatchObject({ errors: 1, events: 1 });

    stub.reply = () => ({ status: 400, body: '{"error":"bad"}' });
    stub.requests.length = 0;
    const c = await start();
    await postEvents(c, { name: "a.b" });
    await flush();
    expect(
      c.logs.find((l) => l["msg"] === "umami batch rejected"),
    ).toMatchObject({
      status: 400,
    });
  });

  it("never fails the request when Umami is down", async () => {
    await stub.close();
    const b = await start();
    expect((await postEvents(b, { name: "a.b" })).statusCode).toBe(202);
    await flush();
    expect(b.logs.some((l) => l["msg"] === "umami batch failed")).toBe(true);
    stub = await startStubUmami(); // for afterEach
  });
});
