// Wire types of the Catraca HTTP API. Field names and optionality follow the
// JSON tags of the Go types they mirror (internal/event, internal/decision,
// internal/audit): a field that is `omitempty` in Go is optional here.
//
// Times are RFC 3339 strings. Durations (retry_after) are Go time.Duration
// values, which encode as integer nanoseconds.

/** The kind of event. Mirrors event.Type. */
export type EventType = "send" | "feedback" | "account" | "key_leak";

/** The outcome carried by a feedback event. Mirrors event.FeedbackKind. */
export type FeedbackKind = "bounce" | "complaint" | "delivery";

/** A delivery outcome. Mirrors event.FeedbackInfo. */
export interface FeedbackInfo {
  kind: FeedbackKind;
  /** "permanent" or "transient", for bounces. */
  bounce_type?: string;
  recipient?: string;
  /** The platform's id for the email the feedback is about. */
  message_id?: string;
}

/** Account activity and what the platform knows about the account. Mirrors event.AccountInfo. */
export interface AccountInfo {
  /** For example "signup", "login", "api_key_created" or "domain_added". */
  action?: string;
  /** When the account was created. Without it Catraca uses the first time it saw the account. */
  created_at?: string;
  plan?: string;
}

/** Where a leaked key was found. Mirrors event.LeakInfo. */
export interface LeakInfo {
  source?: string;
  url?: string;
}

/** Every field an event may carry. Mirrors event.Event. */
export interface EventFields {
  id?: string;
  type: EventType;
  /** When it happened. Catraca uses its own clock when it is absent. */
  time?: string;
  account_id?: string;
  api_key_id?: string;
  ip?: string;
  from?: string;
  to?: string[];
  subject?: string;
  links?: string[];
  feedback?: FeedbackInfo;
  account?: AccountInfo;
  leak?: LeakInfo;
  /** Platform-specific values, exposed to rules as event.attributes. */
  attributes?: Record<string, string>;
}

/** An email the platform is about to send. */
export interface SendEvent extends EventFields {
  type: "send";
  account_id: string;
}

/** A bounce, complaint or delivery. */
export interface FeedbackEvent extends EventFields {
  type: "feedback";
  account_id: string;
  feedback: FeedbackInfo;
}

/** Account activity: signup, login, a new API key or domain. */
export interface AccountEvent extends EventFields {
  type: "account";
  account_id: string;
}

/** An API key found in public. */
export interface KeyLeakEvent extends EventFields {
  type: "key_leak";
  api_key_id: string;
}

/** An event, with the fields its type requires (event.Event.Validate). */
export type CatracaEvent = SendEvent | FeedbackEvent | AccountEvent | KeyLeakEvent;

/** What the platform should do. Mirrors decision.Action, from least to most severe. */
export type Action = "allow" | "flag" | "throttle" | "hold" | "block";

/** Whether a rule acts (enforce) or only records what it would have done (shadow). */
export type Mode = "shadow" | "enforce";

/** A rule that matched the event. Mirrors decision.Match. */
export interface Match {
  rule_id: string;
  reason: string;
  action: Action;
  mode: Mode;
  effects?: string[];
  /** Nanoseconds. */
  retry_after?: number;
  /** The rule could not be evaluated and matched only because it fails closed. */
  errored?: boolean;
}

/** A rule that could not be evaluated. Mirrors decision.RuleError. */
export interface RuleError {
  rule_id: string;
  error: string;
}

/** Catraca's answer for one event. Mirrors decision.Decision. */
export interface Decision {
  id: string;
  event_id?: string;
  time: string;
  action: Action;
  /** Nanoseconds; set when action is "throttle". */
  retry_after?: number;
  /** The enforced rules that matched. */
  matches?: Match[];
  /** The shadow rules that matched: what would have happened. */
  shadow?: Match[];
  errors?: RuleError[];
  /** Some signals were missing, for example because the store timed out. */
  degraded?: boolean;
  ruleset_version: string;
  latency_us: number;
}

/** The body of POST /v1/decide and POST /v1/events. */
export interface DecisionResponse {
  decision: Decision;
}

/** A person's judgment of a match. Mirrors audit.Verdict. */
export type Verdict = "true_positive" | "false_positive";

/** A label to give a decision, or one rule that matched it. Mirrors audit.Label. */
export interface Label {
  /** The rule the verdict is about. Without it the verdict applies to every rule that matched. */
  rule_id?: string;
  verdict: Verdict;
  /** Who gave the label: a person, or a system such as an appeals flow. */
  by: string;
  reason?: string;
  /** When the verdict was given. Catraca uses its own clock when it is absent. */
  time?: string;
}

/** A label as the audit log returns it. */
export interface StoredLabel extends Label {
  time: string;
}

/** What the audit log keeps of an event: no message content. Mirrors audit.StoredEvent. */
export interface StoredEvent {
  id?: string;
  type: EventType;
  time: string;
  account_id: string;
  api_key_id?: string;
  ip?: string;
  from_domain?: string;
  recipients?: number;
  recipient_domains?: string[];
  /** The first 16 hex digits of the SHA-256 of the subject. */
  subject_sha256?: string;
  feedback_kind?: FeedbackKind;
  bounce_type?: string;
  account_action?: string;
  /** The whole event, when the audit log keeps full events. */
  full?: EventFields & { time: string; account_id: string };
}

/** A decision in the audit log, with its event and labels. Mirrors audit.Entry. */
export interface DecisionEntry {
  decision: Decision;
  event: StoredEvent;
  /** Oldest first. */
  labels: StoredLabel[];
}

/** The body of every /v1 error. */
export interface ErrorBody {
  error: {
    /** A stable, machine-readable name for the problem, such as "invalid_event". */
    code: string;
    message: string;
    details?: string[];
  };
}
