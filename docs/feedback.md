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

SNS retries a delivery only on 5xx and 429 answers. Catraca answers 503 when
it cannot fetch the signing certificate and 500 when it could not record any
event of a notification, so those are retried; everything else, including
forgeries and notifications without an account, gets a final answer.

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

useSend retries any non-2xx answer up to six times; Catraca answers 5xx only
when it could not record the feedback.

## Generic endpoint

For providers Catraca has no adapter for, the platform posts one feedback
event in Catraca's own format to `POST /v1/feedback`:

```http
POST /v1/feedback HTTP/1.1
Content-Type: application/json
Catraca-Signature: t=1760529600,v1=5f1c...e9

{
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

- `type` may be omitted; when present it must be `feedback`.
- `account_id` and `feedback.kind` (`bounce`, `complaint` or `delivery`) are
  required; bounces also need `bounce_type` (`permanent` or `transient`).
- `time` defaults to when Catraca receives the event. `from` is the sender
  address of the original email, so the sender domain's counters see the
  feedback too.
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
`400` explains what is wrong with the event, and `401` means the signature
did not verify.

## Metrics

Every handler reports what it did through `OnOutcome`, with a small, fixed
set of values meant for a metric label: `decided`, `ignored`, `no_account`,
`invalid_signature`, `topic_not_allowed`, `cert_unavailable`, `malformed`,
`too_large`, `decide_failed`, `subscription_confirmed`,
`subscription_failed` and `unsubscribed`. A rising `no_account` usually
means emails are being sent without the tag or header; a rising
`invalid_signature` means someone other than the provider is posting to the
endpoint, or a secret was rotated on one side only.
