import hashlib
import hmac
import json
from datetime import datetime

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

    esp_name = "Forward Email"

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
        # Treat a blank/empty key the same as unset, so an empty config value
        # can't silently disable the insecure-webhook warning.
        if not webhook_signing_key:
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

    @staticmethod
    def _parse_timestamp(value):
        """Parse an ISO 8601 timestamp, or return None if absent/invalid."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None


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

        bounced_at = esp_event.get("bounced_at")
        timestamp = self._parse_timestamp(bounced_at)

        # Forward Email's bounce payload identifies the send by its internal
        # email_id (not the Message-ID header), shared across recipients. Combine
        # it with the recipient and the failure time so a deferral and a later
        # bounce for the same recipient remain distinct (not deduplicated away).
        email_id = esp_event.get("email_id")
        recipient = esp_event.get("recipient")
        id_parts = [str(part) for part in (email_id, recipient, bounced_at) if part]
        event_id = "-".join(id_parts) or None

        # Recover the metadata and tags that the backend encoded into the
        # outbound X-Metadata/X-Tags headers, if Forward Email echoes the
        # original message headers back in the bounce payload.
        metadata, tags = self._decode_metadata_and_tags(esp_event.get("headers"))

        return AnymailTrackingEvent(
            event_type=event_type,
            timestamp=timestamp,
            message_id=email_id,
            event_id=event_id,
            recipient=recipient,
            reject_reason=reject_reason,
            description=esp_event.get("message"),
            metadata=metadata,
            tags=tags,
            # Prefer the full SMTP server response; fall back to the parsed
            # bounce reason if Forward Email didn't include a raw response.
            mta_response=esp_event.get("response") or bounce.get("message"),
            esp_event=esp_event,
        )

    @staticmethod
    def _decode_metadata_and_tags(headers):
        """Recover metadata/tags from echoed-back X-Metadata/X-Tags headers."""
        # Headers may be a dict, a list of [name, value] pairs, or a list of
        # {"name"/"key", "value"/"line"} objects; handle each defensively.
        metadata = {}
        tags = []
        items = []
        if isinstance(headers, dict):
            items = list(headers.items())
        elif isinstance(headers, list):
            for header in headers:
                if isinstance(header, dict):
                    name = header.get("name", header.get("key"))
                    value = header.get("value", header.get("line"))
                    if name is not None:
                        items.append((name, value))
                elif isinstance(header, (list, tuple)) and len(header) == 2:
                    items.append((header[0], header[1]))
        for name, value in items:
            key = str(name).lower()
            if key == "x-metadata":
                try:
                    metadata = json.loads(value)
                except (TypeError, ValueError):
                    pass
            elif key == "x-tags":
                try:
                    tags = json.loads(value)
                except (TypeError, ValueError):
                    pass
        return metadata, tags


class ForwardEmailInboundWebhookView(ForwardEmailBaseWebhookView):
    """Handler for Forward Email inbound (webhook forwarding) messages"""

    signal = inbound

    def parse_events(self, request):
        esp_event = json.loads(request.body.decode("utf-8"))
        # Forward Email may group several aliases that share one webhook URL into
        # a single POST, listing every delivered address in `recipients`. Emit
        # one inbound event per recipient (a single event when there's just one).
        recipients = esp_event.get("recipients") or [None]
        return [self.esp_to_anymail_event(esp_event, r) for r in recipients]

    def esp_to_anymail_event(self, esp_event, recipient=None):
        raw_mime = esp_event.get("raw")
        if raw_mime:
            message = AnymailInboundMessage.parse_raw_mime(raw_mime)
        else:
            # Fall back to constructing from Forward Email's parsed fields.
            message = self.message_from_parsed(esp_event)

        # Envelope (SMTP) sender/recipient come from the SMTP session.
        # Forward Email's inbound session uses `sender` for the MAIL FROM;
        # fall back to mailFrom.address for other payload shapes. (mailFrom may
        # be explicitly null for some automated/bounce messages.)
        session = esp_event.get("session") or {}
        mail_from = session.get("mailFrom") or {}
        message.envelope_sender = (
            session.get("sender") or mail_from.get("address") or None
        )
        message.envelope_recipient = recipient or session.get("recipient")

        # Forward Email runs a spam scanner and may include a score.
        spam_score = esp_event.get("spamScore")
        if spam_score is not None:
            try:
                message.spam_score = float(spam_score)
            except (TypeError, ValueError):
                pass
        if "isSpam" in esp_event:
            message.spam_detected = bool(esp_event["isSpam"])

        message_id = esp_event.get("messageId") or message.get("Message-ID")
        event_id = "-".join(str(p) for p in (message_id, recipient) if p) or None
        return AnymailInboundEvent(
            event_type=EventType.INBOUND,
            # SMTP arrival time, if Forward Email provided it.
            timestamp=self._parse_timestamp(
                session.get("arrivalDate") or session.get("arrivalTime")
            ),
            event_id=event_id,
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
        raw_headers = None
        if isinstance(headers, str):
            # With `?raw=false`, Forward Email delivers headers as a raw block.
            raw_headers = headers
            headers = None
        elif isinstance(headers, dict):
            # mailparser may serialize headers as an object of name: value.
            headers = list(headers.items())

        if headers is not None:
            # AnymailInboundMessage.construct sets From/To/Cc/Bcc/Subject from the
            # dedicated args below, so drop those from the extra headers to avoid
            # duplicate singleton headers (which can flip from_email to a list).
            singleton_headers = {"from", "to", "cc", "bcc", "subject"}
            headers = [
                (name, value)
                for name, value in headers
                if str(name).lower() not in singleton_headers
            ]

        attachments = [
            att
            for att in (
                self._construct_attachment(raw_att)
                for raw_att in esp_event.get("attachments") or []
            )
            if att is not None
        ]

        # mailparser serializes an absent text/html body as `false`; coerce any
        # non-string body to None so construct() doesn't build a bogus part.
        text = esp_event.get("text")
        html = esp_event.get("html")
        return AnymailInboundMessage.construct(
            raw_headers=raw_headers,
            from_email=address_field(esp_event.get("from")),
            to=address_field(esp_event.get("to")),
            cc=address_field(esp_event.get("cc")),
            subject=esp_event.get("subject"),
            headers=headers,
            text=text if isinstance(text, str) else None,
            html=html if isinstance(html, str) else None,
            attachments=attachments or None,
        )

    @staticmethod
    def _construct_attachment(att):
        """Build an AnymailInboundMessage attachment from a parsed FE attachment."""
        if not isinstance(att, dict):
            return None
        content = att.get("content")
        base64 = False
        if isinstance(content, dict) and content.get("type") == "Buffer":
            # mailparser serializes Buffer content as {"type":"Buffer","data":[...]}
            try:
                content = bytes(content.get("data") or [])
            except (TypeError, ValueError):
                return None
        elif isinstance(content, str):
            # Assume base64-encoded content for string payloads.
            base64 = True
        elif not isinstance(content, (bytes, bytearray)):
            return None

        return AnymailInboundMessage.construct_attachment(
            content_type=att.get("contentType") or "application/octet-stream",
            content=content,
            filename=att.get("filename"),
            content_id=att.get("contentId") or att.get("cid"),
            base64=base64,
        )
