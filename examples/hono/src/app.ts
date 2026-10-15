// An email API in the shape of a sending platform: POST /emails asks Catraca
// before every send and does what the decision says.
import { Hono, type Context } from "hono";

import {
  reasons,
  retryAfterSeconds,
  type Catraca,
  type ClientDecision,
  type SendEvent,
} from "../../client-ts/src/index.ts";

/** An email as a customer submits it. */
export interface Email {
  from: string;
  to: string[];
  subject: string;
  text?: string;
  html?: string;
}

/** The customer behind an API key. */
export interface Customer {
  accountId: string;
  apiKeyId: string;
}

/** Delivers email. A real platform would hand it to SES, Postal or an MTA. */
export interface Sender {
  send(customer: Customer, email: Email): Promise<string>;
}

/** Where held emails wait for a person to review them. */
export interface ReviewQueue {
  hold(customer: Customer, email: Email, decision: ClientDecision): Promise<void>;
}

export interface AppOptions {
  catraca: Pick<Catraca, "decide">;
  sender: Sender;
  review: ReviewQueue;
  /** Returns the customer an API key belongs to, or undefined. */
  authenticate: (apiKey: string) => Customer | undefined;
  /**
   * Returns the IP the request came from. Signals such as new IPs and keys
   * used from many places depend on it, so take it from the connection, or
   * from a proxy header only when a proxy you trust sets it.
   */
  clientIp?: (c: Context) => string | undefined;
  /** Receives one structured log line at a time. Default: JSON on stdout. */
  log?: (line: Record<string, unknown>) => void;
}

const maxRecipients = 50;

export function createApp(options: AppOptions): Hono {
  const log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  const app = new Hono();

  app.post("/emails", async (c) => {
    const apiKey = c.req.header("Authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
    const customer = apiKey ? options.authenticate(apiKey) : undefined;
    if (!customer) {
      return c.json({ error: "unauthorized" }, 401);
    }
    const email = parseEmail(await c.req.json().catch(() => undefined));
    if (typeof email === "string") {
      return c.json({ error: "invalid_email", message: email }, 400);
    }

    const event: SendEvent = {
      type: "send",
      account_id: customer.accountId,
      api_key_id: customer.apiKeyId,
      from: email.from,
      to: email.to,
      subject: email.subject,
    };
    const links = extractLinks(`${email.text ?? ""} ${email.html ?? ""}`);
    if (links.length > 0) {
      event.links = links;
    }
    const ip = options.clientIp?.(c);
    if (ip) {
      event.ip = ip;
    }
    const decision = await options.catraca.decide(event);
    const ruleIds = (decision.matches ?? []).map((m) => m.rule_id);
    if (decision.fail_open) {
      log({ level: "warn", msg: "catraca unavailable; sending without a check", account_id: customer.accountId, ...decision.fail_open });
    }

    switch (decision.action) {
      case "allow":
      case "flag": {
        const messageId = await options.sender.send(customer, email);
        if (decision.action === "flag") {
          log({ level: "info", msg: "catraca flagged a send", decision_id: decision.id, message_id: messageId, account_id: customer.accountId, rules: ruleIds });
        }
        return c.json({ id: messageId, status: "sent", decision_id: decision.id }, 200);
      }
      case "throttle": {
        const seconds = retryAfterSeconds(decision) ?? 1;
        c.header("Retry-After", String(seconds));
        return c.json({ error: "throttled", retry_after: seconds, reasons: reasons(decision), decision_id: decision.id }, 429);
      }
      case "hold":
        await options.review.hold(customer, email, decision);
        log({ level: "info", msg: "catraca held a send for review", decision_id: decision.id, account_id: customer.accountId, rules: ruleIds });
        return c.json({ status: "queued_for_review", decision_id: decision.id }, 202);
      case "block":
        return c.json({ error: "blocked", reasons: reasons(decision), decision_id: decision.id }, 403);
    }
  });

  app.onError((err, c) => {
    log({ level: "error", msg: "request failed", error: err.message });
    return c.json({ error: "internal" }, 500);
  });

  return app;
}

/** Returns the email in body, or why it is not one. */
export function parseEmail(body: unknown): Email | string {
  if (typeof body !== "object" || body === null) {
    return "the body must be a JSON object";
  }
  const b = body as Record<string, unknown>;
  if (typeof b.from !== "string" || !b.from.includes("@")) {
    return "from must be an email address";
  }
  if (!Array.isArray(b.to) || b.to.length === 0 || b.to.length > maxRecipients || !b.to.every((t) => typeof t === "string" && t.includes("@"))) {
    return `to must be a list of 1 to ${maxRecipients} email addresses`;
  }
  if (typeof b.subject !== "string") {
    return "subject must be a string";
  }
  const email: Email = { from: b.from, to: b.to as string[], subject: b.subject };
  for (const field of ["text", "html"] as const) {
    const v = b[field];
    if (v === undefined) continue;
    if (typeof v !== "string") return `${field} must be a string`;
    email[field] = v;
  }
  if (email.text === undefined && email.html === undefined) {
    return "text or html is required";
  }
  return email;
}

/** Returns the distinct http and https URLs in s, in order, without trailing punctuation. */
export function extractLinks(s: string): string[] {
  const urls = (s.match(/https?:\/\/[^\s"'<>]+/gi) ?? []).map((u) => u.replace(/[.,;:!?)\]]+$/, ""));
  return [...new Set(urls)];
}
