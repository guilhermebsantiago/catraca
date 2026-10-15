// Runs the example on Node: node src/server.ts
import { serve } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";

import { Catraca } from "../../client-ts/src/index.ts";
import { createApp, type Customer } from "./app.ts";
import { FakeSender, MemoryReviewQueue } from "./memory.ts";

const env = process.env;
const token = env.CATRACA_TOKEN;
if (!token) {
  console.error("set CATRACA_TOKEN to the bearer token of your Catraca server");
  process.exit(1);
}

const catraca = new Catraca({
  baseUrl: env.CATRACA_URL ?? "http://localhost:8080",
  token,
  // A send should not wait long for a check; past this, fail open.
  timeoutMs: Number(env.CATRACA_TIMEOUT_MS ?? 250),
  failOpen: true,
});

// The platform's own API keys. A real platform looks them up in its database.
const customers = new Map<string, Customer>([
  ["demo-key", { accountId: "acct_demo", apiKeyId: "key_demo" }],
]);

const app = createApp({
  catraca,
  sender: new FakeSender(),
  review: new MemoryReviewQueue(),
  authenticate: (apiKey) => customers.get(apiKey),
  clientIp: (c) => getConnInfo(c).remote.address,
});

const port = Number(env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`listening on http://localhost:${info.port}, asking Catraca at ${env.CATRACA_URL ?? "http://localhost:8080"}`);
});
