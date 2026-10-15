// A stand-in for Catraca on a loopback port, for tests.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: unknown;
}

export type Handler = (req: RecordedRequest, res: ServerResponse) => void;

export interface MockCatraca {
  url: string;
  requests: RecordedRequest[];
  /** Replaces how the server answers. */
  handle(handler: Handler): void;
  close(): Promise<void>;
}

/** Answers with status and a JSON body. */
export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

/** Starts a mock Catraca that answers every request with handler. */
export async function startMock(handler: Handler = (_req, res) => json(res, 404, {})): Promise<MockCatraca> {
  let current = handler;
  const requests: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const recorded: RecordedRequest = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: text === "" ? undefined : JSON.parse(text),
      };
      requests.push(recorded);
      current(recorded, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    handle(h) {
      current = h;
    },
    close() {
      server.closeAllConnections();
      return new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

/** Returns a loopback URL where nothing listens. */
export async function closedPortUrl(): Promise<string> {
  const mock = await startMock();
  await mock.close();
  return mock.url;
}
