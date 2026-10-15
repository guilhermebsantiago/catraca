// In-memory stand-ins for the parts of a platform this example does not
// build: delivering email and the review queue.
import type { ClientDecision } from "../../client-ts/src/index.ts";
import type { Customer, Email, ReviewQueue, Sender } from "./app.ts";

/** Pretends to deliver email and remembers what it "sent". */
export class FakeSender implements Sender {
  readonly sent: { id: string; customer: Customer; email: Email }[] = [];

  async send(customer: Customer, email: Email): Promise<string> {
    const id = `msg_${this.sent.length + 1}`;
    this.sent.push({ id, customer, email });
    return id;
  }
}

/** Keeps held emails in memory until someone reviews them. */
export class MemoryReviewQueue implements ReviewQueue {
  readonly held: { customer: Customer; email: Email; decision: ClientDecision }[] = [];

  async hold(customer: Customer, email: Email, decision: ClientDecision): Promise<void> {
    this.held.push({ customer, email, decision });
  }
}
