import hashlib
import hmac
import json

from django.utils.crypto import constant_time_compare

from ..exceptions import AnymailWebhookValidationFailure
from ..inbound import AnymailInboundMessage
from ..signals import (
    AnymailInboundEvent,
    AnymailTrackingEvent,
    EventType,
    RejectReason,
    inbound,
    tracking,
)
from ..utils import get_anymail_setting
from .base import AnymailBaseWebhookView


class ForwardEmailBaseWebhookView(AnymailBaseWebhookView):
    """Base view class for Forward Email webhooks"""

    esp_name = "ForwardEmail"

    # (Declaring class attr allows override by kwargs in View.as_view.)
    webhook_signing_key = None

    def __init__(self, **kwargs):
        # Forward Email signs webhook payloads with a per-domain
        # "Webhook Signature Payload Verification Key". If it's configured,
        # signature verification is sufficient and basic auth isn't required.
        webhook_signing_key = get_anymail_setting(
            "webhook_signing_key",
            esp_name=self.esp_name,
            kwargs=kwargs,
            default=None,
        )
        if webhook_signing_key is None:
            self._webhook_signing_key = None
            self.warn_if_no_basic_auth = True
        else:
            # hmac.new requires bytes key:
            self._webhook_signing_key = webhook_signing_key.encode("utf-8")
            self.warn_if_no_basic_auth = False
        super().__init__(**kwargs)

    def validate_request(self, request):
        super().validate_request(request)  # first check basic auth if enabled
        if self._webhook_signing_key is None:
            # No signing key configured; rely on basic auth (checked above).
            return
        try:
            signature = request.headers["X-Webhook-Signature"]
        except KeyError as err:
            raise AnymailWebhookValidationFailure(
                "Forward Email webhook called without X-Webhook-Signature header"
            ) from err
        # Forward Email computes an HMAC-SHA256 hex digest of the raw request body.
        expected_signature = hmac.new(
            key=self._webhook_signing_key,
            msg=request.body,
            digestmod=hashlib.sha256,
        ).hexdigest()
        if not constant_time_compare(signature, expected_signature):
            raise AnymailWebhookValidationFailure(
                "Forward Email webhook called with incorrect signature"
            )


class ForwardEmailTrackingWebhookView(ForwardEmailBaseWebhookView):
    """Handler for Forward Email bounce (delivery failure) webhooks"""

    signal = tracking

    # Map Forward Email bounce category to Anymail normalized RejectReason.
    reject_reasons = {
        "block": RejectReason.BLOCKED,
        "blocked": RejectReason.BLOCKED,
        "spam": RejectReason.SPAM,
        "virus": RejectReason.SPAM,
        "recipient": RejectReason.BOUNCED,
        "message": RejectReason.BOUNCED,
        "network": RejectReason.OTHER,
        "protocol": RejectReason.OTHER,
    }

    def parse_events(self, request):
        esp_event = json.loads(request.body.decode("utf-8"))
        return [self.esp_to_anymail_event(esp_event)]

    def esp_to_anymail_event(self, esp_event):
        bounce = esp_event.get("bounce") or {}

        # Distinguish soft (4xx -> deferred) from hard (5xx -> bounced) failures,
        # using the extended status ("4.x.x"/"5.x.x") then the SMTP code.
        status = str(bounce.get("status") or "")
        code = bounce.get("code")
        if status.startswith("4") or (isinstance(code, int) and 400 <= code < 500):
            event_type = EventType.DEFERRED
        else:
            event_type = EventType.BOUNCED

        category = (bounce.get("category") or "").lower()
        if event_type == EventType.DEFERRED:
            reject_reason = None
        else:
            reject_reason = self.reject_reasons.get(category, RejectReason.BOUNCED)

        return AnymailTrackingEvent(
            event_type=event_type,
            timestamp=None,  # Forward Email doesn't provide an event timestamp
            # Forward Email's bounce payload identifies the message by its
            # internal email_id (not the Message-ID header).
            message_id=esp_event.get("email_id"),
            event_id=esp_event.get("email_id"),
            recipient=esp_event.get("recipient"),
            reject_reason=reject_reason,
            description=esp_event.get("message"),
            mta_response=bounce.get("message"),
            esp_event=esp_event,
        )


class ForwardEmailInboundWebhookView(ForwardEmailBaseWebhookView):
    """Handler for Forward Email inbound (webhook forwarding) messages"""

    signal = inbound

    def parse_events(self, request):
        esp_event = json.loads(request.body.decode("utf-8"))
        return [self.esp_to_anymail_event(esp_event)]

    def esp_to_anymail_event(self, esp_event):
        raw_mime = esp_event.get("raw")
        if raw_mime:
            message = AnymailInboundMessage.parse_raw_mime(raw_mime)
        else:
            # Fall back to constructing from Forward Email's parsed fields.
            message = self.message_from_parsed(esp_event)

        # Envelope (SMTP) sender/recipient come from the SMTP session.
        session = esp_event.get("session") or {}
        message.envelope_sender = session.get("mailFrom", {}).get("address") or None
        recipients = esp_event.get("recipients") or []
        message.envelope_recipient = session.get("recipient") or (
            recipients[0] if recipients else None
        )

        # Forward Email runs a spam scanner and may include a score.
        spam_score = esp_event.get("spamScore")
        if spam_score is not None:
            try:
                message.spam_score = float(spam_score)
            except (TypeError, ValueError):
                pass
        if "isSpam" in esp_event:
            message.spam_detected = bool(esp_event["isSpam"])

        return AnymailInboundEvent(
            event_type=EventType.INBOUND,
            timestamp=None,
            event_id=esp_event.get("messageId") or message.get("Message-ID"),
            esp_event=esp_event,
            message=message,
        )

    def message_from_parsed(self, esp_event):
        """Construct a message from Forward Email's parsed (mailparser) fields."""

        def address_field(value):
            # mailparser address objects look like {"text": "...", "value": [...]}.
            if isinstance(value, dict):
                return value.get("text")
            if isinstance(value, list):
                return ", ".join(
                    item.get("text", "") if isinstance(item, dict) else str(item)
                    for item in value
                )
            return value

        headers = esp_event.get("headers")
        # mailparser may serialize headers as a list of [name, value] pairs.
        if isinstance(headers, dict):
            headers = list(headers.items())

        return AnymailInboundMessage.construct(
            from_email=address_field(esp_event.get("from")),
            to=address_field(esp_event.get("to")),
            cc=address_field(esp_event.get("cc")),
            subject=esp_event.get("subject"),
            headers=headers,
            text=esp_event.get("text"),
            html=esp_event.get("html"),
        )
