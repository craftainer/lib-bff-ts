import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { LightMyRequestResponse } from "fastify";
import { makeBff, type TestBff } from "./bff.ts";

/** Analytics routes never touch the IdP, so nothing listens here. */
const NO_IDP = { issuer: "http://127.0.0.1:1" };

/** A BFF with the given `ANALYTICS_*` overrides. */
export function makeAnalyticsBff(
  env: Record<string, string> = {},
): Promise<TestBff> {
  return makeBff(NO_IDP, { env: { ANALYTICS_BACKEND: "log", ...env } });
}

/** `POST /bff/analytics` the way the SPA does (same origin, `X-CSRF: 1`). */
export function postEvents(
  bff: TestBff,
  payload: unknown,
  headers: Record<string, string> = {},
  remoteAddress?: string,
): Promise<LightMyRequestResponse> {
  return bff.app.inject({
    method: "POST",
    url: "/bff/analytics",
    headers: { "x-csrf": "1", "content-type": "application/json", ...headers },
    payload: JSON.stringify(payload),
    ...(remoteAddress === undefined ? {} : { remoteAddress }),
  });
}

/** The analytics log lines captured so far. */
export function eventLogs(bff: TestBff): Record<string, unknown>[] {
  return bff.logs.filter((l) => l["msg"] === "analytics_event");
}

export interface Recorded {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage["headers"];
  body: string;
}

/** A stub Umami: records every request and answers with `reply`. */
export interface StubUmami {
  url: string;
  requests: Recorded[];
  reply: (req: Recorded) => {
    status: number;
    body?: string;
    headers?: Record<string, string>;
    delayMs?: number;
  };
  close(): Promise<void>;
}

export async function startStubUmami(): Promise<StubUmami> {
  const requests: Recorded[] = [];
  const stub: StubUmami = {
    url: "",
    requests,
    reply: () => ({ status: 200, body: '{"size":1,"processed":1,"errors":0}' }),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const recorded: Recorded = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      requests.push(recorded);
      const answer = stub.reply(recorded);
      setTimeout(() => {
        res.writeHead(answer.status, answer.headers);
        res.end(answer.body ?? "");
      }, answer.delayMs ?? 0);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  stub.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return stub;
}
