import hashlib
import hmac
import json
from textwrap import dedent
from unittest.mock import ANY

from django.test import override_settings, tag

from anymail.inbound import AnymailInboundMessage
from anymail.signals import AnymailInboundEvent, EventType

from .webhook_cases import WebhookBasicAuthTestCase, WebhookTestCase

TEST_SIGNING_KEY = "test_webhook_signing_key"

SAMPLE_RAW_MIME = dedent("""\
    From: "Sender Name" <from@example.org>
    To: "Recipient" <inbound@example.com>
    Subject: Test inbound message
    Message-ID: <CAabc123@mail.example.org>
    Content-Type: text/plain; charset="UTF-8"

    This is the inbound message body.
    """)


def forwardemail_signature(body, key=TEST_SIGNING_KEY):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


class ForwardEmailInboundTestCase(WebhookTestCase):
    def client_post_signed(self, url, json_data, signing_key=TEST_SIGNING_KEY):
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
class ForwardEmailInboundWebhookTests(ForwardEmailInboundTestCase):
    def test_inbound_raw_mime(self):
        payload = {
            "raw": SAMPLE_RAW_MIME,
            "recipients": ["inbound@example.com"],
            "session": {
                "recipient": "inbound@example.com",
                # Forward Email's inbound session uses `sender` for MAIL FROM.
                "sender": "envelope-from@example.org",
                "arrivalDate": "2022-10-11T12:13:14.000Z",
            },
            "messageId": "<CAabc123@mail.example.org>",
        }
        response = self.client_post_signed("/anymail/forwardemail/inbound/", payload)
        self.assertEqual(response.status_code, 200)

        kwargs = self.assert_handler_called_once_with(
            self.inbound_handler,
            sender=ANY,
            event=ANY,
            esp_name="ForwardEmail",
        )
        event = kwargs["event"]
        self.assertIsInstance(event, AnymailInboundEvent)
        self.assertEqual(event.event_type, EventType.INBOUND)
        self.assertEqual(event.timestamp.isoformat(), "2022-10-11T12:13:14+00:00")
        message = event.message
        self.assertIsInstance(message, AnymailInboundMessage)
        self.assertEqual(message.from_email.display_name, "Sender Name")
        self.assertEqual(message.from_email.addr_spec, "from@example.org")
        self.assertEqual(message.subject, "Test inbound message")
        self.assertEqual(message.text.strip(), "This is the inbound message body.")
        self.assertEqual(message.envelope_sender, "envelope-from@example.org")
        self.assertEqual(message.envelope_recipient, "inbound@example.com")

    def test_inbound_spam(self):
        payload = {
            "raw": SAMPLE_RAW_MIME,
            "recipients": ["inbound@example.com"],
            "spamScore": 7.5,
            "isSpam": True,
        }
        response = self.client_post_signed("/anymail/forwardemail/inbound/", payload)
        self.assertEqual(response.status_code, 200)
        message = self.get_kwargs(self.inbound_handler)["event"].message
        self.assertEqual(message.spam_score, 7.5)
        self.assertIs(message.spam_detected, True)

    def test_inbound_parsed_fallback(self):
        """When `raw` is absent, build from Forward Email's parsed fields"""
        payload = {
            "from": {"text": "Sender Name <from@example.org>"},
            "to": {"text": "inbound@example.com"},
            "subject": "Parsed subject",
            "text": "Parsed body",
            "html": "<p>Parsed body</p>",
            "recipients": ["inbound@example.com"],
        }
        response = self.client_post_signed("/anymail/forwardemail/inbound/", payload)
        self.assertEqual(response.status_code, 200)
        message = self.get_kwargs(self.inbound_handler)["event"].message
        self.assertEqual(message.subject, "Parsed subject")
        self.assertEqual(message.from_email.addr_spec, "from@example.org")
        self.assertEqual(message.text, "Parsed body")
        self.assertEqual(message.html, "<p>Parsed body</p>")
        self.assertEqual(message.envelope_recipient, "inbound@example.com")

    def test_inbound_parsed_raw_headers_and_attachments(self):
        """With ?raw=false, headers may be a raw string and attachments a list."""
        import base64

        payload = {
            "from": {"text": "Sender Name <from@example.org>"},
            "to": {"text": "inbound@example.com"},
            "subject": "Parsed subject",
            "headers": (
                "From: Sender Name <from@example.org>\r\n"
                "Subject: Parsed subject\r\n"
                "X-Custom: custom-value\r\n"
            ),
            "text": "Parsed body",
            "recipients": ["inbound@example.com"],
            "attachments": [
                {
                    "filename": "doc.txt",
                    "contentType": "text/plain",
                    "content": base64.b64encode(b"file contents").decode("ascii"),
                },
                {
                    # mailparser may serialize binary content as a Buffer object.
                    "filename": "raw.bin",
                    "contentType": "application/octet-stream",
                    "content": {"type": "Buffer", "data": [1, 2, 3]},
                },
            ],
        }
        response = self.client_post_signed("/anymail/forwardemail/inbound/", payload)
        self.assertEqual(response.status_code, 200)
        message = self.get_kwargs(self.inbound_handler)["event"].message
        self.assertEqual(message["X-Custom"], "custom-value")
        attachments = message.attachments
        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[0].get_filename(), "doc.txt")
        self.assertEqual(attachments[0].get_content_text(), "file contents")
        self.assertEqual(attachments[1].get_filename(), "raw.bin")
        self.assertEqual(attachments[1].get_content_bytes(), b"\x01\x02\x03")

    def test_inbound_null_mailfrom(self):
        # mailFrom may be explicitly null (e.g. for bounce/automated messages);
        # this must not crash.
        payload = {
            "raw": SAMPLE_RAW_MIME,
            "recipients": ["inbound@example.com"],
            "session": {"mailFrom": None, "recipient": "inbound@example.com"},
        }
        response = self.client_post_signed("/anymail/forwardemail/inbound/", payload)
        self.assertEqual(response.status_code, 200)
        message = self.get_kwargs(self.inbound_handler)["event"].message
        self.assertIsNone(message.envelope_sender)
        self.assertEqual(message.envelope_recipient, "inbound@example.com")

    def test_invalid_signature_rejected(self):
        body = json.dumps({"raw": SAMPLE_RAW_MIME})
        response = self.client.post(
            "/anymail/forwardemail/inbound/",
            content_type="application/json",
            data=body.encode("utf-8"),
            headers={"X-Webhook-Signature": "wrong"},
        )
        self.assertEqual(response.status_code, 400)


@tag("forwardemail")
class ForwardEmailInboundBasicAuthTestCase(WebhookBasicAuthTestCase):
    should_warn_if_no_auth = True

    def call_webhook(self):
        return self.client.post(
            "/anymail/forwardemail/inbound/",
            content_type="application/json",
            data=json.dumps({"raw": SAMPLE_RAW_MIME}),
        )
