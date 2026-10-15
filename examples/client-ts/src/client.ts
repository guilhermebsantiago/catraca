import type {
  CatracaEvent,
  Decision,
  DecisionEntry,
  DecisionResponse,
  ErrorBody,
  Label,
} from "./types.ts";

export interface CatracaOptions {
  /** Where Catraca listens, for example "http://catraca.internal:8080". */
  baseUrl: string;
  /** The bearer token for the /v1 routes. */
  token: string;
  /** How long a request may take, in milliseconds. Default 1000. */
  timeoutMs?: number;
  /**
   * When true, decide and record never throw because Catraca is unavailable:
   * when it cannot be reached, times out, answers with a server error (5xx)
   * or with a body that is not a decision, they return an allow decision with
   * `fail_open` set, so the platform keeps sending. Errors that mean the
   * request itself is wrong (4xx: a bad token, an invalid event) still throw,
   * so they are found and fixed instead of silently turning detection off.
   * Default false.
   */
  failOpen?: boolean;
  /** The fetch to use. Default globalThis.fetch. */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  /** Cancels the request. A canceled request throws its reason; it never fails open. */
  signal?: AbortSignal;
  /** Overrides CatracaOptions.timeoutMs for this request. */
  timeoutMs?: number;
}

/** Why a request failed. */
export type FailureKind = "timeout" | "network" | "http" | "invalid_response";

/** A request to Catraca failed. */
export class CatracaError extends Error {
  readonly kind: FailureKind;
  /** The HTTP status, when Catraca answered. */
  readonly status: number | undefined;
  /** Catraca's error code, such as "invalid_event", when it sent one. */
  readonly code: string | undefined;
  readonly details: readonly string[];

  constructor(
    kind: FailureKind,
    message: string,
    init: { status?: number; code?: string; details?: string[]; cause?: unknown } = {},
  ) {
    super(message, { cause: init.cause });
    this.name = "CatracaError";
    this.kind = kind;
    this.status = init.status;
    this.code = init.code;
    this.details = init.details ?? [];
  }

  /** Whether the failure is Catraca being unavailable, rather than a bad request. */
  get unavailable(): boolean {
    return this.kind !== "http" || (this.status !== undefined && this.status >= 500);
  }
}

/** Set on a decision the client made itself because Catraca was unavailable. */
export interface FailOpen {
  kind: FailureKind;
  message: string;
  status?: number;
}

/**
 * A decision as the client returns it. `fail_open` is never sent by Catraca:
 * the client sets it on the allow decision it returns when it fails open, and
 * then `id` and `ruleset_version` are empty, since Catraca recorded nothing.
 */
export interface ClientDecision extends Decision {
  fail_open?: FailOpen;
}

const defaultTimeoutMs = 1000;

/** A small client for the Catraca HTTP API. */
export class Catraca {
  readonly #baseUrl: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  readonly #failOpen: boolean;
  readonly #fetch: typeof fetch;

  constructor(options: CatracaOptions) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new TypeError(`catraca: baseUrl must be http or https, got ${url.protocol}`);
    }
    if (!options.token) {
      throw new TypeError("catraca: a token is required");
    }
    this.#baseUrl = url.href.replace(/\/+$/, "");
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
    this.#failOpen = options.failOpen ?? false;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  /** Decides an event, typically a send, synchronously: POST /v1/decide. */
  decide(event: CatracaEvent, options?: RequestOptions): Promise<ClientDecision> {
    return this.#decision("/v1/decide", event, options);
  }

  /** Records an event, such as feedback or account activity: POST /v1/events. */
  record(event: CatracaEvent, options?: RequestOptions): Promise<ClientDecision> {
    return this.#decision("/v1/events", event, options);
  }

  /**
   * Labels a decision: POST /v1/decisions/{id}/labels. A reversal, such as
   * unblocking a sender after an appeal, is a false_positive. Returns the
   * decision with all its labels.
   */
  async label(decisionId: string, label: Label, options?: RequestOptions): Promise<DecisionEntry> {
    const body = await this.#request("POST", decisionPath(decisionId) + "/labels", label, options);
    return entryOf(body);
  }

  /** Returns a decision with its event and labels, or null when Catraca has no such decision. */
  async getDecision(decisionId: string, options?: RequestOptions): Promise<DecisionEntry | null> {
    try {
      return entryOf(await this.#request("GET", decisionPath(decisionId), undefined, options));
    } catch (err) {
      if (err instanceof CatracaError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async #decision(path: string, event: CatracaEvent, options?: RequestOptions): Promise<ClientDecision> {
    try {
      const body = await this.#request("POST", path, event, options);
      const decision = (body as Partial<DecisionResponse> | null)?.decision;
      if (!isDecision(decision)) {
        throw new CatracaError("invalid_response", `catraca: ${path} did not answer with a decision`);
      }
      return decision;
    } catch (err) {
      if (this.#failOpen && err instanceof CatracaError && err.unavailable) {
        return failOpenDecision(err);
      }
      throw err;
    }
  }

  async #request(method: string, path: string, body: unknown, options: RequestOptions = {}): Promise<unknown> {
    const timeout = AbortSignal.timeout(options.timeoutMs ?? this.#timeoutMs);
    const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.#token}`,
    };
    const init: RequestInit = { method, headers, signal };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    let text: string;
    let status: number;
    try {
      const res = await this.#fetch(this.#baseUrl + path, init);
      status = res.status;
      text = await res.text();
    } catch (err) {
      if (options.signal?.aborted) {
        throw options.signal.reason;
      }
      if (timeout.aborted) {
        throw new CatracaError("timeout", `catraca: ${method} ${path} timed out`, { cause: err });
      }
      throw new CatracaError("network", `catraca: ${method} ${path}: ${messageOf(err)}`, { cause: err });
    }

    let parsed: unknown;
    try {
      parsed = text === "" ? undefined : JSON.parse(text);
    } catch (err) {
      if (status >= 200 && status < 300) {
        throw new CatracaError("invalid_response", `catraca: ${method} ${path}: the answer is not JSON`, { status, cause: err });
      }
    }
    if (status < 200 || status >= 300) {
      const apiError = (parsed as Partial<ErrorBody> | undefined)?.error;
      const init: { status: number; code?: string; details?: string[] } = { status };
      if (typeof apiError?.code === "string") init.code = apiError.code;
      if (Array.isArray(apiError?.details)) init.details = apiError.details;
      const reason = typeof apiError?.message === "string" ? apiError.message : `HTTP ${status}`;
      throw new CatracaError("http", `catraca: ${method} ${path}: ${reason}`, init);
    }
    return parsed;
  }
}

/**
 * How many seconds a throttled sender should wait, rounded up and at least 1,
 * as a Retry-After header wants it; undefined when the decision is not a
 * throttle.
 */
export function retryAfterSeconds(decision: Decision): number | undefined {
  if (decision.action !== "throttle") {
    return undefined;
  }
  return Math.max(1, Math.ceil((decision.retry_after ?? 0) / 1e9));
}

/** The reasons of the enforced rules behind a decision, without duplicates. */
export function reasons(decision: Decision): string[] {
  return [...new Set((decision.matches ?? []).map((m) => m.reason))];
}

function decisionPath(id: string): string {
  if (!id) {
    throw new TypeError("catraca: a decision id is required");
  }
  return `/v1/decisions/${encodeURIComponent(id)}`;
}

const actions = new Set(["allow", "flag", "throttle", "hold", "block"]);

function isDecision(v: unknown): v is Decision {
  if (typeof v !== "object" || v === null) {
    return false;
  }
  const d = v as Record<string, unknown>;
  return typeof d.id === "string" && typeof d.action === "string" && actions.has(d.action);
}

function entryOf(body: unknown): DecisionEntry {
  const e = body as Partial<DecisionEntry> | undefined;
  if (!isDecision(e?.decision) || !Array.isArray(e?.labels)) {
    throw new CatracaError("invalid_response", "catraca: the answer is not a decision entry");
  }
  return e as DecisionEntry;
}

function failOpenDecision(err: CatracaError): ClientDecision {
  const failOpen: FailOpen = { kind: err.kind, message: err.message };
  if (err.status !== undefined) {
    failOpen.status = err.status;
  }
  return {
    id: "",
    time: new Date().toISOString(),
    action: "allow",
    ruleset_version: "",
    latency_us: 0,
    fail_open: failOpen,
  };
}

function messageOf(err: unknown): string {
  if (err instanceof Error) {
    const cause = err.cause instanceof Error ? `: ${err.cause.message}` : "";
    return err.message + cause;
  }
  return String(err);
}
