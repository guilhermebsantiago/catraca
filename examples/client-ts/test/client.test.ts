import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";

import { Catraca, CatracaError, reasons, retryAfterSeconds } from "../src/index.ts";
import type { Decision, DecisionEntry, SendEvent } from "../src/index.ts";
import { closedPortUrl, json, startMock, type MockCatraca } from "./mock-server.ts";

const send: SendEvent = {
  type: "send",
  account_id: "acct_42",
  api_key_id: "key_1",
  ip: "203.0.113.7",
  from: "hello@shop.example",
  to: ["ana@mail.example"],
  subject: "Your receipt",
  links: ["https://shop.example/r/1"],
};

const allow: Decision = {
  id: "01J9ZK3Q7V",
  time: "2026-10-15T12:00:00Z",
  action: "allow",
  ruleset_version: "d1354ae8bf5f",
  latency_us: 412,
};

const throttle: Decision = {
  ...allow,
  action: "throttle",
  retry_after: 60,
  matches: [
    {
      rule_id: "new-account-burst",
      reason: "New account sending at burst volume",
      action: "throttle",
      mode: "enforce",
      retry_after: 60,
    },
  ],
};

const entry: DecisionEntry = {
  decision: allow,
  event: { type: "send", time: "2026-10-15T12:00:00Z", account_id: "acct_42", recipients: 1 },
  labels: [],
};

describe("Catraca client", () => {
  let mock: MockCatraca;
  let client: Catraca;
  let failOpen: Catraca;

  before(async () => {
    mock = await startMock();
    client = new Catraca({ baseUrl: mock.url, token: "secret", timeoutMs: 200 });
    failOpen = new Catraca({ baseUrl: mock.url, token: "secret", timeoutMs: 200, failOpen: true });
  });
  after(() => mock.close());
  beforeEach(() => {
    mock.requests.length = 0;
  });

  it("decides an event", async () => {
    mock.handle((_req, res) => json(res, 200, { decision: throttle }));
    const d = await client.decide(send);
    assert.deepEqual(d, throttle);
    const [req] = mock.requests;
    assert.equal(req?.method, "POST");
    assert.equal(req?.url, "/v1/decide");
    assert.equal(req?.headers.authorization, "Bearer secret");
    assert.equal(req?.headers["content-type"], "application/json");
    assert.deepEqual(req?.body, send);
  });

  it("records an event", async () => {
    mock.handle((_req, res) => json(res, 202, { decision: allow }));
    const d = await client.record({
      type: "feedback",
      account_id: "acct_42",
      feedback: { kind: "complaint", recipient: "ana@mail.example" },
    });
    assert.equal(d.action, "allow");
    assert.equal(mock.requests[0]?.url, "/v1/events");
  });

  it("gets a decision", async () => {
    mock.handle((req, res) => (req.url === "/v1/decisions/a%2Fb" ? json(res, 200, entry) : json(res, 404, {})));
    assert.deepEqual(await client.getDecision("a/b"), entry);
    assert.equal(mock.requests[0]?.method, "GET");
    assert.equal(mock.requests[0]?.body, undefined);
  });

  it("returns null for a decision Catraca does not have", async () => {
    mock.handle((_req, res) => json(res, 404, { error: { code: "not_found", message: "no such decision" } }));
    assert.equal(await client.getDecision("missing"), null);
  });

  it("labels a decision", async () => {
    const labeled: DecisionEntry = {
      ...entry,
      labels: [{ verdict: "false_positive", by: "support", reason: "appeal", time: "2026-10-15T13:00:00Z" }],
    };
    mock.handle((_req, res) => json(res, 201, labeled));
    const got = await client.label(allow.id, { verdict: "false_positive", by: "support", reason: "appeal" });
    assert.deepEqual(got, labeled);
    assert.equal(mock.requests[0]?.url, `/v1/decisions/${allow.id}/labels`);
    assert.deepEqual(mock.requests[0]?.body, { verdict: "false_positive", by: "support", reason: "appeal" });
  });

  it("throws Catraca's error for a bad request, even when failing open", async () => {
    mock.handle((_req, res) =>
      json(res, 400, { error: { code: "invalid_event", message: "event: account_id is required", details: ["x"] } }),
    );
    for (const c of [client, failOpen]) {
      await assert.rejects(c.decide(send), (err: unknown) => {
        assert.ok(err instanceof CatracaError);
        assert.equal(err.kind, "http");
        assert.equal(err.status, 400);
        assert.equal(err.code, "invalid_event");
        assert.deepEqual(err.details, ["x"]);
        assert.match(err.message, /account_id is required/);
        assert.equal(err.unavailable, false);
        return true;
      });
    }
  });

  it("throws on a bad token, even when failing open", async () => {
    mock.handle((_req, res) => json(res, 401, { error: { code: "unauthorized", message: "bad token" } }));
    await assert.rejects(failOpen.decide(send), { name: "CatracaError", status: 401 });
  });

  it("fails open on a server error", async () => {
    mock.handle((_req, res) => json(res, 503, { error: { code: "no_ruleset", message: "no ruleset is loaded" } }));
    await assert.rejects(client.decide(send), { name: "CatracaError", kind: "http", status: 503 });
    const d = await failOpen.decide(send);
    assert.equal(d.action, "allow");
    assert.equal(d.id, "");
    assert.equal(d.fail_open?.kind, "http");
    assert.equal(d.fail_open?.status, 503);
  });

  it("fails open on a timeout", async () => {
    mock.handle(() => {
      // Never answer.
    });
    await assert.rejects(client.decide(send), { name: "CatracaError", kind: "timeout" });
    const started = Date.now();
    const d = await failOpen.decide(send, { timeoutMs: 50 });
    assert.ok(Date.now() - started < 1000, "the per-request timeout was not used");
    assert.equal(d.action, "allow");
    assert.equal(d.fail_open?.kind, "timeout");
  });

  it("fails open when the answer is not a decision", async () => {
    for (const reply of ["not json", JSON.stringify({ decision: { action: "explode" } }), ""]) {
      mock.handle((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(reply);
      });
      await assert.rejects(client.decide(send), { name: "CatracaError", kind: "invalid_response" });
      assert.equal((await failOpen.decide(send)).fail_open?.kind, "invalid_response");
    }
  });

  it("rethrows the caller's abort instead of failing open", async () => {
    mock.handle(() => {});
    const controller = new AbortController();
    const pending = failOpen.decide(send, { signal: controller.signal });
    controller.abort(new Error("caller gave up"));
    await assert.rejects(pending, { message: "caller gave up" });
  });

  it("does not fail open for label and getDecision", async () => {
    mock.handle((_req, res) => json(res, 500, { error: { code: "internal", message: "boom" } }));
    await assert.rejects(failOpen.getDecision("x"), { name: "CatracaError", status: 500 });
    await assert.rejects(failOpen.label("x", { verdict: "true_positive", by: "me" }), { status: 500 });
  });
});

describe("Catraca client without a server", () => {
  it("fails open when Catraca cannot be reached", async () => {
    const url = await closedPortUrl();
    const client = new Catraca({ baseUrl: url, token: "t" });
    await assert.rejects(client.decide(send), { name: "CatracaError", kind: "network" });
    const d = await new Catraca({ baseUrl: url, token: "t", failOpen: true }).decide(send);
    assert.equal(d.action, "allow");
    assert.equal(d.fail_open?.kind, "network");
  });

  it("joins the base URL and the route", async () => {
    let seen = "";
    const fetchStub: typeof fetch = async (input) => {
      seen = String(input);
      return new Response(JSON.stringify({ decision: allow }), { status: 200 });
    };
    await new Catraca({ baseUrl: "https://abuse.example/catraca/", token: "t", fetch: fetchStub }).decide(send);
    assert.equal(seen, "https://abuse.example/catraca/v1/decide");
  });

  it("rejects bad options", () => {
    assert.throws(() => new Catraca({ baseUrl: "ftp://x", token: "t" }), TypeError);
    assert.throws(() => new Catraca({ baseUrl: "http://x", token: "" }), TypeError);
    assert.throws(() => new Catraca({ baseUrl: "not a url", token: "t" }), TypeError);
  });
});

describe("helpers", () => {
  it("turns retry_after into Retry-After seconds", () => {
    assert.equal(retryAfterSeconds(throttle), 60);
    assert.equal(retryAfterSeconds({ ...throttle, retry_after: 2 }), 2);
    const { retry_after: _, ...noDelay } = throttle;
    assert.equal(retryAfterSeconds(noDelay), 1);
    assert.equal(retryAfterSeconds(allow), undefined);
  });

  it("lists the reasons of enforced matches", () => {
    const m = throttle.matches?.[0];
    assert.ok(m);
    const d: Decision = {
      ...allow,
      action: "block",
      matches: [m, { ...m, rule_id: "other" }, { ...m, reason: "Leaked key" }],
      shadow: [{ ...m, reason: "shadow only", mode: "shadow" }],
    };
    assert.deepEqual(reasons(d), ["New account sending at burst volume", "Leaked key"]);
    assert.deepEqual(reasons(allow), []);
  });
});
