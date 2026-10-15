import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";

import { Catraca, type Decision, type Match } from "../../client-ts/src/index.ts";
import { closedPortUrl, json, startMock, type MockCatraca } from "../../client-ts/test/mock-server.ts";
import { createApp, extractLinks, parseEmail, type AppOptions } from "../src/app.ts";
import { FakeSender, MemoryReviewQueue } from "../src/memory.ts";

const customer = { accountId: "acct_demo", apiKeyId: "key_demo" };

const email = {
  from: "hello@shop.example",
  to: ["ana@mail.example"],
  subject: "Your receipt",
  text: "Thanks! See https://shop.example/r/1 or https://shop.example/r/1",
  html: '<a href="https://bit.ly/abc">track</a>',
};

function decision(action: Decision["action"], matches: Match[] = []): Decision {
  return { id: "dec_1", time: "2026-10-15T12:00:00Z", action, matches, ruleset_version: "v1", latency_us: 300 };
}

function match(ruleId: string, action: Decision["action"], reason: string, extra: Partial<Match> = {}): Match {
  return { rule_id: ruleId, reason, action, mode: "enforce", ...extra };
}

describe("POST /emails", () => {
  let mock: MockCatraca;
  let sender: FakeSender;
  let review: MemoryReviewQueue;
  let logs: Record<string, unknown>[];
  let app: ReturnType<typeof createApp>;

  function build(catraca: AppOptions["catraca"]) {
    return createApp({
      catraca,
      sender,
      review,
      authenticate: (key) => (key === "demo-key" ? customer : undefined),
      clientIp: (c) => c.req.header("X-Test-IP"),
      log: (line) => logs.push(line),
    });
  }

  function post(body: unknown, key = "demo-key", target = app) {
    return target.request("/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "X-Test-IP": "203.0.113.7" },
      body: JSON.stringify(body),
    });
  }

  function answer(d: Decision) {
    mock.handle((_req, res) => json(res, 200, { decision: d }));
  }

  before(async () => {
    mock = await startMock();
  });
  after(() => mock.close());
  beforeEach(() => {
    mock.requests.length = 0;
    sender = new FakeSender();
    review = new MemoryReviewQueue();
    logs = [];
    app = build(new Catraca({ baseUrl: mock.url, token: "secret", timeoutMs: 200, failOpen: true }));
  });

  it("asks Catraca about the send, then sends on allow", async () => {
    answer(decision("allow"));
    const res = await post(email);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { id: "msg_1", status: "sent", decision_id: "dec_1" });
    assert.equal(sender.sent.length, 1);
    assert.equal(mock.requests[0]?.url, "/v1/decide");
    assert.equal(mock.requests[0]?.headers.authorization, "Bearer secret");
    assert.deepEqual(mock.requests[0]?.body, {
      type: "send",
      account_id: "acct_demo",
      api_key_id: "key_demo",
      ip: "203.0.113.7",
      from: email.from,
      to: email.to,
      subject: email.subject,
      links: ["https://shop.example/r/1", "https://bit.ly/abc"],
    });

    answer(decision("allow"));
    await post({ from: email.from, to: email.to, subject: "No links", text: "plain" });
    assert.equal((mock.requests[1]?.body as Record<string, unknown>).links, undefined);
  });

  it("sends and logs on flag", async () => {
    answer(decision("flag", [match("shortener-links-new-account", "flag", "New account linking through a URL shortener")]));
    const res = await post(email);
    assert.equal(res.status, 200);
    assert.equal(sender.sent.length, 1);
    assert.deepEqual(logs, [
      {
        level: "info",
        msg: "catraca flagged a send",
        decision_id: "dec_1",
        message_id: "msg_1",
        account_id: "acct_demo",
        rules: ["shortener-links-new-account"],
      },
    ]);
  });

  it("answers 429 with Retry-After on throttle", async () => {
    const d = decision("throttle", [match("new-account-burst", "throttle", "Slow down", { retry_after: 60e9 })]);
    answer({ ...d, retry_after: 60e9 });
    const res = await post(email);
    assert.equal(res.status, 429);
    assert.equal(res.headers.get("Retry-After"), "60");
    assert.deepEqual(await res.json(), { error: "throttled", retry_after: 60, reasons: ["Slow down"], decision_id: "dec_1" });
    assert.equal(sender.sent.length, 0);
  });

  it("queues the email for review on hold", async () => {
    answer(decision("hold", [match("complaint-rate-high", "hold", "Spam complaint rate above 0.3%")]));
    const res = await post(email);
    assert.equal(res.status, 202);
    assert.deepEqual(await res.json(), { status: "queued_for_review", decision_id: "dec_1" });
    assert.equal(sender.sent.length, 0);
    assert.equal(review.held.length, 1);
    assert.equal(review.held[0]?.email.subject, email.subject);
  });

  it("answers 403 with the reasons on block", async () => {
    answer(
      decision("block", [
        match("leaked-key-send", "block", "This API key was found in public"),
        match("other", "hold", "Something else"),
      ]),
    );
    const res = await post(email);
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), {
      error: "blocked",
      reasons: ["This API key was found in public", "Something else"],
      decision_id: "dec_1",
    });
    assert.equal(sender.sent.length, 0);
  });

  it("ignores shadow matches", async () => {
    answer({ ...decision("allow"), shadow: [match("key-many-ips", "hold", "Many IPs", { mode: "shadow" })] });
    const res = await post(email);
    assert.equal(res.status, 200);
    assert.equal(sender.sent.length, 1);
  });

  it("keeps sending when Catraca is unreachable", async () => {
    const down = build(new Catraca({ baseUrl: await closedPortUrl(), token: "secret", failOpen: true }));
    const res = await post(email, "demo-key", down);
    assert.equal(res.status, 200);
    assert.equal(sender.sent.length, 1);
    assert.equal(logs[0]?.level, "warn");
    assert.equal(logs[0]?.kind, "network");
  });

  it("answers 500 when Catraca rejects the request", async () => {
    mock.handle((_req, res) => json(res, 401, { error: { code: "unauthorized", message: "bad token" } }));
    const res = await post(email);
    assert.equal(res.status, 500);
    assert.equal(sender.sent.length, 0);
    assert.equal(logs[0]?.level, "error");
  });

  it("checks the API key and the body before asking Catraca", async () => {
    assert.equal((await post(email, "wrong-key")).status, 401);
    assert.equal((await post({ ...email, to: [] })).status, 400);
    const res = await app.request("/emails", { method: "POST", headers: { Authorization: "Bearer demo-key" }, body: "{" });
    assert.equal(res.status, 400);
    assert.equal(mock.requests.length, 0);
  });
});

describe("parseEmail", () => {
  it("accepts an email with text or html", () => {
    assert.deepEqual(parseEmail({ from: "a@x.example", to: ["b@y.example"], subject: "s", text: "t" }), {
      from: "a@x.example",
      to: ["b@y.example"],
      subject: "s",
      text: "t",
    });
  });

  it("explains what is wrong", () => {
    const ok = { from: "a@x.example", to: ["b@y.example"], subject: "s", text: "t" };
    for (const [body, want] of [
      [null, /JSON object/],
      [{ ...ok, from: "nobody" }, /from/],
      [{ ...ok, to: "b@y.example" }, /to must/],
      [{ ...ok, to: Array(51).fill("b@y.example") }, /to must/],
      [{ ...ok, subject: 1 }, /subject/],
      [{ ...ok, html: 2 }, /html must/],
      [{ from: ok.from, to: ok.to, subject: "s" }, /text or html/],
    ] as const) {
      const got = parseEmail(body);
      assert.equal(typeof got, "string");
      assert.match(got as string, want);
    }
  });
});

describe("extractLinks", () => {
  it("finds distinct http and https links", () => {
    assert.deepEqual(extractLinks('go to https://a.example/x, <a href="http://b.example/y?z=1">b</a> (https://a.example/x).'), [
      "https://a.example/x",
      "http://b.example/y?z=1",
    ]);
    assert.deepEqual(extractLinks("no links here"), []);
  });
});
