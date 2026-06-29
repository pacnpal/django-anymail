import hashlib
import hmac
import json
from unittest.mock import ANY

from django.test import override_settings, tag

from anymail.signals import AnymailTrackingEvent, EventType, RejectReason

from .webhook_cases import WebhookBasicAuthTestCase, WebhookTestCase

TEST_SIGNING_KEY = "test_webhook_signing_key"


def forwardemail_signature(body, key=TEST_SIGNING_KEY):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


class ForwardEmailWebhookTestCase(WebhookTestCase):
    def client_post_signed(self, url, json_data, signing_key=TEST_SIGNING_KEY):
        """POST json_data to url with a valid X-Webhook-Signature header"""
        body = json.dumps(json_data)
        headers = {}
        if signing_key is not None:
            headers["X-Webhook-Signature"] = forwardemail_signature(body, signing_key)
        return self.client.post(
            url,
            content_type="application/json",
            data=body.encode("utf-8"),
            headers=headers,
        )


@tag("forwardemail")
@override_settings(ANYMAIL_FORWARDEMAIL_WEBHOOK_SIGNING_KEY=TEST_SIGNING_KEY)
class ForwardEmailWebhookSignatureTestCase(ForwardEmailWebhookTestCase):
    def test_valid_signature(self):
        response = self.client_post_signed(
            "/anymail/forwardemail/tracking/",
            {"email_id": "abc", "recipient": "to@example.com", "bounce": {}},
        )
        self.assertEqual(response.status_code, 200)

    def test_invalid_signature(self):
        body = json.dumps({"email_id": "abc"})
        response = self.client.post(
            "/anymail/forwardemail/tracking/",
            content_type="application/json",
            data=body.encode("utf-8"),
            headers={"X-Webhook-Signature": "not-the-right-signature"},
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_signature(self):
        body = json.dumps({"email_id": "abc"})
        response = self.client.post(
            "/anymail/forwardemail/tracking/",
            content_type="application/json",
            data=body.encode("utf-8"),
        )
        self.assertEqual(response.status_code, 400)

    def test_signing_key_as_view_param(self):
        """The signing key can be provided as a view init kwarg"""
        from anymail.webhooks.forwardemail import ForwardEmailTrackingWebhookView

        view = ForwardEmailTrackingWebhookView(webhook_signing_key="other_key")
        self.assertIsNotNone(view._webhook_signing_key)


@tag("forwardemail")
@override_settings(ANYMAIL_FORWARDEMAIL_WEBHOOK_SIGNING_KEY=TEST_SIGNING_KEY)
class ForwardEmailTrackingWebhookTestCase(ForwardEmailWebhookTestCase):
    def post_bounce(self, payload):
        response = self.client_post_signed("/anymail/forwardemail/tracking/", payload)
        self.assertEqual(response.status_code, 200)
        return response

    def test_hard_bounce(self):
        payload = {
            "email_id": "60a...id",
            "recipient": "bounce@example.com",
            "message": "Message could not be delivered",
            "response": "554 5.7.1 Message Sender Blocked By Receiving Server",
            "bounced_at": "2022-10-11T12:13:14.000Z",
            "bounce": {
                "action": "reject",
                "message": "Message Sender Blocked By Receiving Server",
                "category": "block",
                "code": 554,
                "status": "5.7.1",
            },
        }
        self.post_bounce(payload)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=ANY,
            event=ANY,
            esp_name="ForwardEmail",
        )
        event = kwargs["event"]
        self.assertIsInstance(event, AnymailTrackingEvent)
        self.assertEqual(event.event_type, EventType.BOUNCED)
        self.assertEqual(event.reject_reason, RejectReason.BLOCKED)
        self.assertEqual(event.recipient, "bounce@example.com")
        self.assertEqual(event.message_id, "60a...id")
        # event_id combines email_id + recipient so multi-recipient bounces
        # remain distinguishable.
        self.assertEqual(event.event_id, "60a...id-bounce@example.com")
        # mta_response prefers the full SMTP server response.
        self.assertEqual(
            event.mta_response, "554 5.7.1 Message Sender Blocked By Receiving Server"
        )
        self.assertEqual(event.description, "Message could not be delivered")
        self.assertEqual(event.timestamp.isoformat(), "2022-10-11T12:13:14+00:00")

    def test_bounce_falls_back_to_bounce_message(self):
        # Without a top-level `response`, mta_response uses the parsed reason.
        payload = {
            "email_id": "id9",
            "recipient": "x@example.com",
            "bounce": {"message": "Mailbox full", "category": "recipient", "code": 552},
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.mta_response, "Mailbox full")
        self.assertIsNone(event.timestamp)
        self.assertEqual(event.event_id, "id9-x@example.com")

    def test_soft_bounce_is_deferred(self):
        payload = {
            "email_id": "id2",
            "recipient": "full@example.com",
            "bounce": {"category": "recipient", "code": 451, "status": "4.2.2"},
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.event_type, EventType.DEFERRED)
        # Soft failures don't get a reject_reason
        self.assertIsNone(event.reject_reason)

    def test_metadata_and_tags_from_bounce_headers(self):
        # If Forward Email echoes the outbound headers, recover the X-Metadata
        # and X-Tags that the backend encoded for metadata/tags.
        payload = {
            "email_id": "id5",
            "recipient": "x@example.com",
            "bounce": {"category": "block", "code": 554, "status": "5.7.1"},
            "headers": {
                "X-Metadata": json.dumps({"user_id": "123", "n": 6}),
                "X-Tags": json.dumps(["receipt", "test"]),
            },
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.metadata, {"user_id": "123", "n": 6})
        self.assertEqual(event.tags, ["receipt", "test"])

    def test_metadata_and_tags_from_header_list(self):
        # Headers may also arrive as a list of {name, value} objects.
        payload = {
            "email_id": "id6",
            "recipient": "x@example.com",
            "bounce": {"category": "block", "code": 554},
            "headers": [
                {"name": "X-Tags", "value": json.dumps(["a", "b"])},
                {"name": "Subject", "value": "hi"},
            ],
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.tags, ["a", "b"])
        self.assertEqual(event.metadata, {})

    def test_spam_category_maps_to_spam(self):
        payload = {
            "email_id": "id3",
            "recipient": "x@example.com",
            "bounce": {"category": "spam", "code": 550, "status": "5.7.1"},
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.event_type, EventType.BOUNCED)
        self.assertEqual(event.reject_reason, RejectReason.SPAM)

    def test_unknown_category_defaults_to_bounced(self):
        payload = {
            "email_id": "id4",
            "recipient": "x@example.com",
            "bounce": {"category": "somethingelse", "code": 550},
        }
        self.post_bounce(payload)
        event = self.get_kwargs(self.tracking_handler)["event"]
        self.assertEqual(event.event_type, EventType.BOUNCED)
        self.assertEqual(event.reject_reason, RejectReason.BOUNCED)


@tag("forwardemail")
class ForwardEmailTrackingWebhookBasicAuthTestCase(WebhookBasicAuthTestCase):
    should_warn_if_no_auth = True

    def call_webhook(self):
        return self.client.post(
            "/anymail/forwardemail/tracking/",
            content_type="application/json",
            data=json.dumps({"email_id": "abc", "bounce": {}}),
        )
