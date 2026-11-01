import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface Seen {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

export interface TestUpstream {
  url: string;
  port: number;
  /** Requests received, oldest first. */
  seen: Seen[];
  /** Lets the `/events` handler send its second event. */
  release(): void;
  close(): Promise<void>;
}

/**
 * A tiny upstream API: `/echo` answers JSON describing the request,
 * `/cookie` sets headers the BFF must not relay, `/events` is an SSE stream
 * that sends a second event only after `release()`.
 */
export async function startUpstream(): Promise<TestUpstream> {
  const seen: Seen[] = [];
  let release = (): void => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const entry: Seen = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(entry);
      if (req.url?.startsWith("/events")) {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("data: one\n\n");
        void gate.then(() => {
          res.write("data: two\n\n");
          res.end();
        });
        return;
      }
      if (req.url?.startsWith("/cookie")) {
        res.writeHead(200, {
          "content-type": "application/json",
          "set-cookie": "upstream=1; Path=/",
          "access-control-allow-origin": "*",
          "strict-transport-security": "max-age=1",
          "content-security-policy": "default-src *",
          "x-upstream": "yes",
        });
        res.end("{}");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(entry));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    seen,
    release,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A port nothing listens on. */
export async function deadPort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}
