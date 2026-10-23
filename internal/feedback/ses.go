package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// SESConfig configures the Amazon SES handler.
//
// The account a notification belongs to is read from AccountTag, then from
// AccountHeader; at least one is required. Notifications with neither are
// acknowledged with 200, so SNS does not retry them, and reported as
// OutcomeNoAccount.
type SESConfig struct {
	// Decider receives one feedback event per affected recipient. Required.
	Decider Decider
	// TopicARNs lists the SNS topics accepted. Messages from any other topic
	// are rejected and their subscriptions are never confirmed. Required.
	TopicARNs []string
	// AccountTag is the name of the SES message tag that holds the
	// platform's account id, read from mail.tags. SES publishes tags only
	// through configuration set event publishing, not through identity
	// notifications.
	AccountTag string
	// AccountHeader is the name of an email header that holds the account
	// id, read from mail.headers. Identity notifications include headers
	// only when "Include original headers" is enabled. The header is
	// visible to recipients.
	AccountHeader string
	// FetchCert downloads SNS signing certificates. The default is
	// HTTPCertFetcher(nil). Fetched certificates are cached by URL.
	FetchCert CertFetcher
	// HTTPClient confirms subscriptions by visiting SubscribeURL. The
	// default times out after 10 seconds. Redirects are never followed.
	HTTPClient *http.Client
	// MaxBodyBytes limits the request body. The default is 1 MiB; an SNS
	// message is at most 256 KiB before JSON escaping.
	MaxBodyBytes int64
	// Logger receives errors that are not shown to the caller. The default
	// discards them.
	Logger *slog.Logger
	// OnOutcome, when set, is called once per request outcome and once per
	// event decided, for metrics.
	OnOutcome func(Outcome)
}

type sesHandler struct {
	base
	topics        map[string]bool
	accountTag    string
	accountHeader string
	certs         *certCache
	client        *http.Client
}

// NewSESHandler returns a handler for Amazon SES bounce, complaint and
// delivery notifications delivered by Amazon SNS to an HTTPS subscription.
//
// It verifies the SNS signature (SignatureVersion 1 and 2) with the signing
// certificate, which it fetches only over HTTPS from an
// sns.<region>.amazonaws.com or sns.<region>.amazonaws.com.cn host. It
// confirms subscriptions to allowed topics and accepts both identity
// notifications (notificationType) and configuration set event publishing
// (eventType). Raw message delivery must be disabled on the subscription,
// since raw messages carry no signature.
//
// Status codes follow SNS's retry policy, which retries 5xx and 429 and
// treats every other status as final: a forged, malformed or unwanted
// message gets a 4xx, a message Catraca could not process because of a
// transient failure gets a 5xx.
func NewSESHandler(cfg SESConfig) (http.Handler, error) {
	b, err := newBase(cfg.Decider, cfg.MaxBodyBytes, cfg.Logger, cfg.OnOutcome)
	if err != nil {
		return nil, err
	}
	if len(cfg.TopicARNs) == 0 {
		return nil, errors.New("feedback: SES needs at least one topic ARN")
	}
	if cfg.AccountTag == "" && cfg.AccountHeader == "" {
		return nil, errors.New("feedback: SES needs AccountTag or AccountHeader")
	}
	topics := make(map[string]bool, len(cfg.TopicARNs))
	for _, arn := range cfg.TopicARNs {
		if !strings.HasPrefix(arn, "arn:") {
			return nil, errors.New("feedback: invalid topic ARN " + arn)
		}
		topics[arn] = true
	}
	fetch := cfg.FetchCert
	if fetch == nil {
		fetch = HTTPCertFetcher(nil)
	}
	return &sesHandler{
		base:          b,
		topics:        topics,
		accountTag:    cfg.AccountTag,
		accountHeader: cfg.AccountHeader,
		certs:         newCertCache(fetch),
		client:        noRedirects(cfg.HTTPClient),
	}, nil
}

func (h *sesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var msg snsMessage
	if err := json.Unmarshal(body, &msg); err != nil || msg.Type == "" || msg.TopicArn == "" {
		h.onOutcome(OutcomeMalformed)
		writeError(w, http.StatusBadRequest, "not an SNS message")
		return
	}
	// The topic is checked before the signature so a message for someone
	// else's topic never makes Catraca fetch anything.
	if !h.topics[msg.TopicArn] {
		h.onOutcome(OutcomeTopicNotAllowed)
		h.log.WarnContext(r.Context(), "feedback: SNS topic not allowed", "topic", msg.TopicArn)
		writeError(w, http.StatusForbidden, "topic not allowed")
		return
	}
	if !validSNSURL(msg.SigningCertURL, true) {
		h.onOutcome(OutcomeInvalidSignature)
		writeError(w, http.StatusForbidden, "invalid signature")
		return
	}
	cert, err := h.certs.get(r.Context(), msg.SigningCertURL)
	if err != nil {
		h.onOutcome(OutcomeCertUnavailable)
		h.log.ErrorContext(r.Context(), "feedback: fetching SNS signing certificate",
			"url", msg.SigningCertURL, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	if err := msg.verify(cert); err != nil {
		h.onOutcome(OutcomeInvalidSignature)
		h.log.WarnContext(r.Context(), "feedback: SNS signature rejected",
			"topic", msg.TopicArn, "message_id", msg.MessageID, "error", err)
		writeError(w, http.StatusForbidden, "invalid signature")
		return
	}

	switch msg.Type {
	case snsSubscriptionConfirmation:
		h.confirm(w, r, &msg)
	case snsUnsubscribeConfirmation:
		h.onOutcome(OutcomeUnsubscribed)
		h.log.WarnContext(r.Context(), "feedback: SNS endpoint unsubscribed", "topic", msg.TopicArn)
		writeOK(w)
	case snsNotification:
		h.notification(w, r, &msg)
	}
}

// confirm visits SubscribeURL, which confirms the subscription.
// https://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.confirm.html
func (h *sesHandler) confirm(w http.ResponseWriter, r *http.Request, msg *snsMessage) {
	if !validSNSURL(msg.SubscribeURL, false) {
		h.onOutcome(OutcomeSubscriptionFailed)
		h.log.WarnContext(r.Context(), "feedback: SubscribeURL is not an SNS URL", "topic", msg.TopicArn)
		writeError(w, http.StatusForbidden, "invalid subscribe URL")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	err := func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, msg.SubscribeURL, nil)
		if err != nil {
			return err
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode != http.StatusOK {
			return errors.New("SubscribeURL returned " + resp.Status)
		}
		return nil
	}()
	if err != nil {
		h.onOutcome(OutcomeSubscriptionFailed)
		h.log.ErrorContext(r.Context(), "feedback: confirming SNS subscription",
			"topic", msg.TopicArn, "error", err)
		writeError(w, http.StatusBadGateway, "subscription not confirmed")
		return
	}
	h.onOutcome(OutcomeSubscriptionConfirmed)
	h.log.InfoContext(r.Context(), "feedback: SNS subscription confirmed", "topic", msg.TopicArn)
	writeOK(w)
}

func (h *sesHandler) notification(w http.ResponseWriter, r *http.Request, msg *snsMessage) {
	var n sesNotification
	if err := json.Unmarshal([]byte(msg.Message), &n); err != nil {
		// SES posts a plain text message when an event destination is
		// created ("Successfully validated SNS topic for Amazon SES event
		// publishing."). It is authentic, so it is acknowledged.
		h.onOutcome(OutcomeIgnored)
		writeOK(w)
		return
	}
	evs, outcome := h.events(&n)
	if outcome != "" {
		h.onOutcome(outcome)
		writeOK(w)
		return
	}
	answerDecided(w, h.decideAll(r, "ses", evs))
}

// sesNotification is an SES notification. Identity notifications name their
// type in notificationType, event publishing in eventType; the other fields
// are shared.
// https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html
// https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-contents.html
type sesNotification struct {
	NotificationType string        `json:"notificationType"`
	EventType        string        `json:"eventType"`
	Mail             sesMail       `json:"mail"`
	Bounce           *sesBounce    `json:"bounce"`
	Complaint        *sesComplaint `json:"complaint"`
	Delivery         *sesDelivery  `json:"delivery"`
}

type sesMail struct {
	Timestamp     string      `json:"timestamp"`
	MessageID     string      `json:"messageId"`
	Source        string      `json:"source"`
	Headers       []sesHeader `json:"headers"`
	CommonHeaders struct {
		From []string `json:"from"`
	} `json:"commonHeaders"`
	// Tags maps a tag name to its values. Only event publishing sets it.
	Tags map[string][]string `json:"tags"`
}

type sesHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type sesBounce struct {
	BounceType        string `json:"bounceType"`
	BounceSubType     string `json:"bounceSubType"`
	BouncedRecipients []struct {
		EmailAddress string `json:"emailAddress"`
		Status       string `json:"status"`
	} `json:"bouncedRecipients"`
	Timestamp string `json:"timestamp"`
}

type sesComplaint struct {
	ComplainedRecipients []struct {
		EmailAddress string `json:"emailAddress"`
	} `json:"complainedRecipients"`
	Timestamp             string `json:"timestamp"`
	ComplaintFeedbackType string `json:"complaintFeedbackType"`
	ComplaintSubType      string `json:"complaintSubType"`
}

type sesDelivery struct {
	Recipients []string `json:"recipients"`
	Timestamp  string   `json:"timestamp"`
}

// events turns a notification into feedback events, or returns the outcome
// that explains why it yields none.
func (h *sesHandler) events(n *sesNotification) ([]event.Event, Outcome) {
	kind := n.EventType
	if kind == "" {
		kind = n.NotificationType
	}
	var info event.FeedbackInfo
	var stamp string
	switch {
	case kind == "Bounce" && n.Bounce != nil:
		info.Kind, stamp = event.Bounce, n.Bounce.Timestamp
	case kind == "Complaint" && n.Complaint != nil:
		// A "not-spam" report retracts a complaint instead of making one.
		// https://www.iana.org/assignments/marf-parameters/marf-parameters.xml#marf-parameters-2
		if strings.EqualFold(n.Complaint.ComplaintFeedbackType, "not-spam") {
			return nil, OutcomeIgnored
		}
		info.Kind, stamp = event.Complaint, n.Complaint.Timestamp
	case kind == "Delivery" && n.Delivery != nil:
		info.Kind, stamp = event.Delivery, n.Delivery.Timestamp
	default:
		// Send, Reject, Open, Click, DeliveryDelay, Rendering Failure,
		// Subscription and AmazonSnsSubscriptionSucceeded are not feedback.
		return nil, OutcomeIgnored
	}

	account := h.accountID(&n.Mail)
	if account == "" {
		return nil, OutcomeNoAccount
	}
	info.MessageID = n.Mail.MessageID
	if stamp == "" {
		stamp = n.Mail.Timestamp
	}
	from := n.Mail.Source
	if len(n.Mail.CommonHeaders.From) > 0 {
		from = n.Mail.CommonHeaders.From[0]
	}
	template := event.Event{
		Type:       event.Feedback,
		Time:       parseTime(stamp),
		AccountID:  account,
		From:       bareAddress(from),
		Attributes: map[string]string{"provider": "ses"},
	}

	var evs []event.Event
	switch info.Kind {
	case event.Bounce:
		b := n.Bounce
		info.BounceType = bounceTransient
		if b.BounceType == "Permanent" {
			info.BounceType = bouncePermanent
		}
		// Undetermined bounces count as transient: the hard bounce rate
		// should only grow on evidence.
		template.Attributes["ses_bounce_type"] = b.BounceType
		template.Attributes["bounce_subtype"] = b.BounceSubType
		if len(b.BouncedRecipients) == 0 {
			return feedbackEvents(template, info, nil), ""
		}
		for _, rcpt := range b.BouncedRecipients {
			ev := feedbackEvent(template, info, rcpt.EmailAddress)
			// The DSN status tells a full mailbox (4.2.2) from a policy or
			// spam rejection (5.7.x), which rules may want to tell apart.
			if rcpt.Status != "" {
				ev.Attributes["bounce_status"] = rcpt.Status
			}
			evs = append(evs, ev)
		}
	case event.Complaint:
		c := n.Complaint
		if c.ComplaintFeedbackType != "" {
			template.Attributes["complaint_type"] = c.ComplaintFeedbackType
		}
		if c.ComplaintSubType != "" {
			template.Attributes["complaint_subtype"] = c.ComplaintSubType
		}
		rcpts := make([]string, 0, len(c.ComplainedRecipients))
		for _, rcpt := range c.ComplainedRecipients {
			rcpts = append(rcpts, rcpt.EmailAddress)
		}
		evs = feedbackEvents(template, info, rcpts)
	case event.Delivery:
		evs = feedbackEvents(template, info, n.Delivery.Recipients)
	}
	return evs, ""
}

// accountID reads the account from the configured tag, then header.
func (h *sesHandler) accountID(m *sesMail) string {
	if h.accountTag != "" {
		for _, v := range m.Tags[h.accountTag] {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	if h.accountHeader != "" {
		for _, hd := range m.Headers {
			if strings.EqualFold(hd.Name, h.accountHeader) {
				if v := strings.TrimSpace(hd.Value); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// bareAddress returns the address in "Name <user@example.com>", or s
// trimmed when it does not parse.
func bareAddress(s string) string {
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Address
	}
	return strings.TrimSpace(s)
}
