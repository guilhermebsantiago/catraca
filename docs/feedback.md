# Delivery feedback

Bounces and complaints are the clearest sign that an account is sending
mail people did not ask for. Catraca turns them into `feedback` events, one
per affected recipient, so rules can read `account.bounce_rate_24h`,
`account.hard_bounce_rate_24h`, `account.complaint_rate_24h` and
`domain.complaints_24h`.

| route | source | authentication |
|---|---|---|
| `POST /v1/feedback/ses` | Amazon SES, through Amazon SNS | SNS message signature |
| `POST /v1/feedback/usesend` | useSend webhooks | `X-UseSend-Signature` |
| `POST /v1/feedback` | anything else, in Catraca's format | `Catraca-Signature` |

None of these routes takes the API bearer token: each one is authenticated
by a signature, and a request that fails it is refused before its body is
read as feedback.

Every feedback event needs the platform's account id, the same id the
platform sends with its `send` events. Each section below explains where the
account id comes from. A notification without one is acknowledged (so the
provider does not retry it) and counted as `no_account`.

What Catraca records for each kind:

| kind | `feedback.bounce_type` | notes |
|---|---|---|
| `bounce` | `permanent` or `transient` | SES `Undetermined` bounces count as `transient`: the hard bounce rate only grows on evidence |
| `complaint` | | a `not-spam` feedback report retracts a complaint, so it is ignored |
| `delivery` | | |

Provider details that rules may want go to `event.attributes`: `provider`
(`ses`, `usesend`), `bounce_subtype` (`General`, `MailboxFull`,
`OnAccountSuppressionList`, ...), `bounce_status` (the DSN status, such as
`5.1.1` or `5.7.1`), `complaint_type` (`abuse`, `fraud`, ...) and, for SES,
`ses_bounce_type` and `complaint_subtype`.

## When feedback cannot be counted

When the store fails (Redis refuses connections or answers with an error),
an event's decision comes back `degraded` and `uncounted`: the bounce or
complaint is not in the counters. The feedback endpoints then answer `503`
with `Retry-After: 10`, so the provider delivers the notification again,
instead of a `200` that would lose it. Each event gets an id the provider
keeps from one delivery to the next (below), and an event whose id has
counted does not count again for `engine.dedupe_ttl` (10 minutes; see
[retries](api.md#retries)), so the events of a notification that did count
the first time are not counted twice. The same goes when an event fails for
another reason a retry may fix, such as no ruleset being loaded. Events
refused as invalid keep their answer, `200` for SES and useSend and `400`
for the generic endpoint: they would be refused again.

A store that answers after `engine.deadline` (10 ms) has not failed: the
decision is `degraded`, but the store's round trip goes on in the background
and its writes still apply, so the answer stays `200` and providers are not
asked to retry while Redis is merely slow. The gap is a Redis that does not
answer at all, as when packets are dropped: a decision waiting for a
connection it never gets looks like a slow one, and feedback that arrives
then may be lost. `catraca_dependency_up{dependency="store"}` shows such an
outage.

Set `dedupe_ttl` to outlast the longest retry schedule below. With
`dedupe_ttl: 0s` a notification delivered again counts its events again.

## Amazon SES

SES publishes bounce, complaint and delivery notifications to an Amazon SNS
topic, and SNS posts them to Catraca over HTTPS. Catraca:

1. Refuses messages from topics that are not configured (403).
2. Verifies the SNS signature, versions 1 (SHA1withRSA) and 2
   (SHA256withRSA). The signing certificate is downloaded only over HTTPS,
   only from a host matching `sns.<region>.amazonaws.com` or
   `sns.<region>.amazonaws.com.cn`, without following redirects, and is
   cached by URL. A forged message gets a 403.
3. Confirms the subscription when SNS sends a `SubscriptionConfirmation`
   for an allowed topic, by visiting its `SubscribeURL` after checking that
   it is an SNS URL too.
4. Turns each bounced, complained or delivered recipient into a feedback
   event. Other notifications (sends, opens, clicks, delivery delays) are
   acknowledged and ignored. The event's `from` is the original From
   header when SES includes headers, otherwise the envelope sender
   (`mail.source`), and its time is when the bounce, complaint or delivery
   happened.

SNS retries a delivery only on 5xx and 429 answers, and treats every other
status as final. Catraca answers 503 when it cannot fetch the signing
certificate, and 503 when an event of the notification could not be counted
([above](#when-feedback-cannot-be-counted)), so those are retried; everything
else, including forgeries and notifications without an account, gets a
final answer. SNS ignores `Retry-After` and follows the subscription's
[delivery policy](https://docs.aws.amazon.com/sns/latest/dg/sns-message-delivery-retries.html):
by default three more attempts, 20 seconds apart, each given about 15
seconds to answer, so it gives up about a minute after the first. A policy
of your own may retry for up to an hour (a hard limit), and a dead-letter
queue on the subscription keeps what it gives up on. A redelivered
notification keeps its `MessageId`, and Catraca names the events of a
notification `ses:<MessageId>:<n>`, so they count once.

### Setup with a configuration set (recommended)

Event publishing through a configuration set is the only SES feature that
includes message tags in the notifications, and a tag is the cleanest place
for the account id: recipients never see it.

1. Create a **standard** SNS topic (SES does not publish to FIFO topics):

   ```sh
   aws sns create-topic --name catraca-ses-feedback
   ```

2. Allow SES to publish to it. Replace the region, account id and names:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"Service": "ses.amazonaws.com"},
       "Action": "sns:Publish",
       "Resource": "arn:aws:sns:us-east-1:111122223333:catraca-ses-feedback",
       "Condition": {
         "StringEquals": {
           "AWS:SourceAccount": "111122223333",
           "AWS:SourceArn": "arn:aws:ses:us-east-1:111122223333:configuration-set/catraca"
         }
       }
     }]
   }
   ```

3. Create a configuration set with an SNS event destination for bounces,
   complaints and deliveries:

   ```sh
   aws sesv2 create-configuration-set --configuration-set-name catraca
   aws sesv2 create-configuration-set-event-destination \
     --configuration-set-name catraca \
     --event-destination-name catraca-feedback \
     --event-destination '{"Enabled": true,
       "MatchingEventTypes": ["BOUNCE", "COMPLAINT", "DELIVERY"],
       "SnsDestination": {"TopicArn": "arn:aws:sns:us-east-1:111122223333:catraca-ses-feedback"}}'
   ```

   Deliveries are optional, but without them Catraca cannot tell a quiet
   account from one whose feedback is missing.

4. Configure Catraca with the topic ARN and the tag name, then subscribe
   Catraca's endpoint. Leave **raw message delivery off**: raw messages
   carry no signature and are refused.

   ```sh
   aws sns subscribe \
     --topic-arn arn:aws:sns:us-east-1:111122223333:catraca-ses-feedback \
     --protocol https \
     --notification-endpoint https://catraca.example.com/v1/feedback/ses
   ```

   Catraca confirms the subscription by itself.

5. Send every email with the configuration set and the account tag. With
   the SES v2 API:

   ```json
   {
     "ConfigurationSetName": "catraca",
     "EmailTags": [{"Name": "catraca-account", "Value": "acct_123"}],
     "...": "..."
   }
   ```

   With SMTP or raw email, use SES's headers, which SES removes before
   sending:

   ```
   X-SES-CONFIGURATION-SET: catraca
   X-SES-MESSAGE-TAGS: catraca-account=acct_123
   ```

   Tag values may contain only ASCII letters, digits, `-` and `_`. If your
   account ids contain anything else, tag a mapped id instead.

In Go, the handler is configured like this:

```go
h, err := feedback.NewSESHandler(feedback.SESConfig{
	Decider:    engine,
	TopicARNs:  []string{"arn:aws:sns:us-east-1:111122223333:catraca-ses-feedback"},
	AccountTag: "catraca-account",
})
```

### Setup with identity notifications

SES can also publish feedback for a verified identity without a
configuration set (**Notifications** on the identity, or
`aws ses set-identity-notification-topic`). These notifications never
include tags, so the account id has to travel in an email header:

1. Enable **Include original email headers** for each notification type.
2. Add a header such as `X-Catraca-Account: acct_123` to every email.
3. Set `AccountHeader: "X-Catraca-Account"` instead of (or as a fallback
   to) `AccountTag`.

Recipients can see this header, so use an opaque id. When both are set, the
tag wins and the header is the fallback.

## useSend

[useSend](https://github.com/usesend/useSend) signs every webhook with the
secret shown when the webhook is created: `X-UseSend-Signature` is `v1=`
followed by the hex HMAC-SHA256 of `<X-UseSend-Timestamp>.<raw body>`, and
the timestamp is in Unix milliseconds. Catraca rejects a webhook whose
signature does not match or whose timestamp is more than five minutes away
from its clock, as useSend's SDK does.

Mapped events:

| useSend event | Catraca feedback |
|---|---|
| `email.bounced` | `bounce`; `bounce.type` `Permanent` is `permanent`, `Transient` and `Undetermined` are `transient` |
| `email.complained` | `complaint` |
| `email.delivered` | `delivery` |

Every other event (`email.sent`, `email.opened`, `email.suppressed`,
`contact.*`, `domain.*`, `webhook.test`, ...) is acknowledged and ignored.
useSend sends the email's whole `to` list rather than the recipient a bounce
or complaint was about, so Catraca records one event per address in `to`.

**Account id.** By default it is the payload's `teamId`, which fits a
self-hosted useSend whose teams are the platform's accounts: send your
`send` events with the team id as `account_id`. `AccountMetadataKey` reads
it from `data.metadata[key]` instead. useSend documents `metadata` as the
custom metadata attached to the email, but its code (webhook version
2026-01-18) fills it with event details such as the bounce type, so check
your useSend version before relying on it.

Setup:

1. In useSend, open **Webhooks**, add
   `https://catraca.example.com/v1/feedback/usesend`, and select
   `email.bounced`, `email.complained` and `email.delivered`.
2. Copy the signing secret into Catraca's configuration.

```go
h, err := feedback.NewUseSendHandler(feedback.UseSendConfig{
	Decider: engine,
	Secret:  os.Getenv("USESEND_WEBHOOK_SECRET"),
})
```

useSend treats any answer but a 2xx, or no answer within 10 seconds, as a
failure, and makes six attempts at a webhook call in all, backing off
exponentially from 5 seconds: the last comes about two and a half minutes
after the first. It ignores `Retry-After`. Catraca answers 5xx only when the
feedback could not be counted
([above](#when-feedback-cannot-be-counted)): a 503. Every attempt carries the
same call id, the payload's `id`, as does a call retried by hand from
useSend's dashboard, and Catraca names the events of a call
`usesend:<id>:<n>`, so they count once. useSend disables a webhook once 30
calls in a row have failed all their attempts, which a store outage of a few
minutes can do when feedback flows steadily: check the webhook in useSend
after one, and enable it again if needed.

## Generic endpoint

For providers Catraca has no adapter for, the platform posts one feedback
event in Catraca's own format to `POST /v1/feedback`:

```http
POST /v1/feedback HTTP/1.1
Content-Type: application/json
Catraca-Signature: t=1760529600,v1=5f1c...e9

{
  "id": "fb_9f2c",
  "account_id": "acct_123",
  "time": "2026-10-15T12:00:00Z",
  "from": "news@example.com",
  "feedback": {
    "kind": "bounce",
    "bounce_type": "permanent",
    "recipient": "someone@example.org",
    "message_id": "msg_1"
  },
  "attributes": {"provider": "postmark"}
}
```

- `id` is your id for this feedback event, so that sending it again counts
  it once (see [retries](api.md#retries)): the provider's id for the bounce
  or complaint, say, not the id of the email it is about, which a bounce and
  a complaint share. Without it every sending counts.
- `type` may be omitted; when present it must be `feedback`.
- `account_id` and `feedback.kind` (`bounce`, `complaint` or `delivery`) are
  required; bounces also need `bounce_type` (`permanent` or `transient`).
- `time` defaults to when Catraca receives the event. A time more than
  `engine.max_future_skew` ahead of Catraca's clock is replaced by the
  clock's, and an event older than `engine.max_event_age` (7 days) is
  answered `400`: see [limits](api.md#limits). `from` is the sender address
  of the original email, so the sender domain's counters see the feedback
  too.
- Fields that do not belong to a feedback event (`to`, `subject`, ...) are
  dropped.

`Catraca-Signature` is the scheme Catraca signs its own webhooks with
(see [Hooks](hooks.md#verifying-the-signature)): `t` is the Unix time in
seconds and `v1` the hex HMAC-SHA256 of `<t>.<raw body>` with the shared
secret. The timestamp must be within five minutes of Catraca's clock
(`GenericConfig.Tolerance`). Several `v1` values may be sent while rotating
the secret. In Go, sign with the public
[`signature`](../signature) package:

```go
import "github.com/guilhermebsantiago/catraca/signature"

req.Header.Set(signature.Header, signature.Sign(secret, time.Now(), body))
```

The answer is `202 Accepted` with the decision, as for `POST /v1/events`;
`400` explains what is wrong with the event, `401` means the signature did
not verify, and `503` with `Retry-After` means the event could not be
counted ([above](#when-feedback-cannot-be-counted)): send it again later,
signed anew, with the same `id`.

## Metrics

Every handler reports what it did through `OnOutcome`, with a small, fixed
set of values meant for a metric label: `decided`, `ignored`, `no_account`,
`invalid_signature`, `topic_not_allowed`, `cert_unavailable`, `malformed`,
`too_large`, `decide_failed`, `uncounted` (decided while the store failed,
and answered `503`), `subscription_confirmed`, `subscription_failed` and
`unsubscribed`. An event the engine refuses, such
as one over a [limit](api.md#limits) or older than `engine.max_event_age`,
counts as `malformed`; SES and useSend get a `200` for it, since a retry
would be refused the same way. A rising `no_account` usually
means emails are being sent without the tag or header; a rising
`invalid_signature` means someone other than the provider is posting to the
endpoint, or a secret was rotated on one side only.
