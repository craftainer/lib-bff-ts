import { logs } from "@opentelemetry/api-logs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { TestBff } from "./helpers/bff.ts";
import { makeAnalyticsBff, postEvents } from "./helpers/analytics.ts";

type Record_ = {
  timestamp?: unknown;
  severityNumber?: number;
  severityText?: string;
  body?: unknown;
  attributes?: Record<string, unknown>;
};

let bff: TestBff | undefined;
beforeEach(() => logs.disable());
afterEach(async () => {
  await bff?.app.close();
  bff = undefined;
  logs.disable();
});

async function start(): Promise<TestBff> {
  bff = await makeAnalyticsBff({
    ANALYTICS_BACKEND: "otel",
    ANALYTICS_PROP_KEYS: "plan",
  });
  return bff;
}

function register(
  emit: (record: Record_) => void,
  enabled = true,
): { scopes: string[] } {
  const scopes: string[] = [];
  logs.setGlobalLoggerProvider({
    getLogger: (name: string) => {
      scopes.push(name);
      return { emit, enabled: () => enabled };
    },
  } as never);
  return { scopes };
}

describe("otel adapter", () => {
  it("emits one log record per event with primitive analytics_prop_<key> attributes", async () => {
    const records: Record_[] = [];
    const { scopes } = register((r) => records.push(r));
    const b = await start();
    await postEvents(b, [
      { name: "hero.created", props: { plan: "free" }, url: "/heroes?x=1" },
      { name: "page.viewed" },
    ]);
    expect(scopes).toEqual(["@craftainer/bff"]);
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({
      severityNumber: 9,
      severityText: "INFO",
      body: "analytics_event",
      attributes: {
        analytics_event: "hero.created",
        analytics_url: "/heroes",
        analytics_prop_plan: "free",
      },
    });
    expect(records[0]?.timestamp).toEqual(expect.any(Number));
    expect(records[1]?.attributes).toEqual({
      analytics_event: "page.viewed",
      analytics_url: "/",
    });
    for (const value of Object.values(records[0]?.attributes ?? {})) {
      expect(["string", "number", "boolean"]).toContain(typeof value);
    }
  });

  it("warns once and discards when no LoggerProvider is registered", async () => {
    const b = await start();
    await postEvents(b, { name: "a.b" });
    await postEvents(b, { name: "a.b" });
    const warnings = b.logs.filter((l) =>
      String(l["msg"]).includes("no OpenTelemetry LoggerProvider"),
    );
    expect(warnings).toHaveLength(1);
  });

  it("logs, never surfaces, a throwing provider", async () => {
    register(() => {
      throw new Error("exporter exploded");
    });
    const b = await start();
    const res = await postEvents(b, { name: "a.b" });
    expect(res.statusCode).toBe(202);
    expect(b.logs.some((l) => l["msg"] === "analytics adapter failed")).toBe(
      true,
    );
  });
});
