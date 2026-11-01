import { afterEach, describe, expect, it } from "vitest";
import type { TestBff } from "./helpers/bff.ts";
import {
  eventLogs,
  makeAnalyticsBff,
  postEvents,
} from "./helpers/analytics.ts";

let bff: TestBff | undefined;
afterEach(async () => {
  await bff?.app.close();
  bff = undefined;
});

async function start(env: Record<string, string> = {}): Promise<TestBff> {
  bff = await makeAnalyticsBff({ ANALYTICS_PROP_KEYS: "plan,count", ...env });
  return bff;
}

describe("POST /bff/analytics", () => {
  it("accepts one event: 202 and one flat log line without the visitor token", async () => {
    const b = await start();
    const res = await postEvents(
      b,
      {
        name: "hero.created",
        props: { plan: "free", count: 3 },
        url: "/heroes?q=1#top",
      },
      { "user-agent": "Mozilla/5.0 test" },
    );
    expect(res.statusCode).toBe(202);
    expect(res.body).toBe("");
    const [line, ...rest] = eventLogs(b);
    expect(rest).toEqual([]);
    expect(line).toMatchObject({
      analytics_event: "hero.created",
      analytics_url: "/heroes",
      analytics_prop_plan: "free",
      analytics_prop_count: 3,
    });
    expect(JSON.stringify(line)).not.toMatch(/visitor|127\.0\.0\.1|Mozilla/);
  });

  it("accepts up to 50 events in an array and defaults the url to /", async () => {
    const b = await start();
    const fifty = Array.from({ length: 50 }, () => ({ name: "page.viewed" }));
    expect((await postEvents(b, fifty)).statusCode).toBe(202);
    expect(eventLogs(b)).toHaveLength(50);
    expect(eventLogs(b)[0]).toMatchObject({ analytics_url: "/" });
    expect((await postEvents(b, [...fifty, fifty[0]])).statusCode).toBe(400);
  });

  it.each([
    ["bad name", { name: "pageview" }],
    ["prop off the allowlist", { name: "a.b", props: { secret: "x" } }],
    ["absolute url", { name: "a.b", url: "https://evil.test/" }],
    ["empty array", []],
    ["not an event", "a.b"],
  ])("answers 400 invalid_event for %s", async (_label, body) => {
    const b = await start();
    const res = await postEvents(b, body);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "invalid_event" });
    expect(eventLogs(b)).toEqual([]);
  });

  it("answers 400 for a body that is not JSON and 415 for another content type", async () => {
    const b = await start();
    const malformed = await b.app.inject({
      method: "POST",
      url: "/bff/analytics",
      headers: { "x-csrf": "1", "content-type": "application/json" },
      payload: "{nope",
    });
    expect(malformed.statusCode).toBe(400);
    const plain = await b.app.inject({
      method: "POST",
      url: "/bff/analytics",
      headers: { "x-csrf": "1", "content-type": "application/xml" },
      payload: "a.b",
    });
    expect(plain.statusCode).toBe(415);
  });

  it("limits the body to 16 KB", async () => {
    const b = await start();
    const res = await postEvents(b, {
      name: "a.b",
      props: { plan: "x".repeat(17 * 1024) },
    });
    expect(res.statusCode).toBe(413);
    expect(eventLogs(b)).toEqual([]);
  });

  it("requires X-CSRF", async () => {
    const b = await start();
    const res = await b.app.inject({
      method: "POST",
      url: "/bff/analytics",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "a.b" }),
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "csrf_rejected" });
  });

  it("is rate limited with the configured limit", async () => {
    const b = await start({ RATE_LIMIT_MAX: "2" });
    const statuses: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      statuses.push((await postEvents(b, { name: "a.b" })).statusCode);
    }
    expect(statuses).toEqual([202, 202, 429]);
  });
});

describe("drop rules answer the same 202 and record nothing", () => {
  const body = { name: "a.b" };

  it.each([
    ["analytics disabled", { ANALYTICS_ENABLED: "false" }, {}],
    ["backend none", { ANALYTICS_BACKEND: "none" }, {}],
    ["Sec-GPC: 1", {}, { "sec-gpc": "1" }],
    ["DNT: 1", {}, { dnt: "1" }],
  ])("%s", async (_label, env, headers) => {
    const b = await start(env);
    const res = await postEvents(b, body, headers);
    expect(res.statusCode).toBe(202);
    expect(res.body).toBe("");
    expect(eventLogs(b)).toEqual([]);
  });

  it("drops before validating, so an invalid body learns nothing either", async () => {
    const b = await start();
    const res = await postEvents(b, { name: "bad" }, { "sec-gpc": "1" });
    expect(res.statusCode).toBe(202);
  });

  it("records when the signal is not 1, or when respectGpc is off", async () => {
    const b = await start();
    await postEvents(b, body, { "sec-gpc": "0", dnt: "0" });
    expect(eventLogs(b)).toHaveLength(1);
    await b.app.close();
    const off = await start({ ANALYTICS_RESPECT_GPC: "false" });
    await postEvents(off, body, { "sec-gpc": "1", dnt: "1" });
    expect(eventLogs(off)).toHaveLength(1);
  });

  it("opt-in mode drops until consent is granted", async () => {
    const b = await start({ ANALYTICS_CONSENT: "opt-in" });
    expect((await postEvents(b, body)).statusCode).toBe(202);
    expect(eventLogs(b)).toEqual([]);

    const grant = await b.app.inject({
      method: "POST",
      url: "/bff/consent",
      headers: { "x-csrf": "1", "content-type": "application/json" },
      payload: JSON.stringify({ analytics: true }),
    });
    const cookie = String(grant.headers["set-cookie"]).split(";")[0] as string;
    await postEvents(b, body, { cookie });
    expect(eventLogs(b)).toHaveLength(1);

    // GPC still wins over consent.
    await postEvents(b, body, { cookie, "sec-gpc": "1" });
    expect(eventLogs(b)).toHaveLength(1);
  });

  it("implied mode records without consent", async () => {
    const b = await start({ ANALYTICS_CONSENT: "implied" });
    await postEvents(b, body);
    expect(eventLogs(b)).toHaveLength(1);
  });
});
