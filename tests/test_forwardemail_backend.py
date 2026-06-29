import json
from base64 import b64decode
from datetime import datetime

from django.core import mail
from django.test import SimpleTestCase, override_settings, tag
from django.utils.timezone import (
    get_fixed_timezone,
    override as override_current_timezone,
)

from anymail.exceptions import AnymailAPIError, AnymailUnsupportedFeature
from anymail.message import AnymailMessage, attach_inline_image

from .mock_requests_backend import (
    RequestsBackendMockAPITestCase,
    SessionSharingTestCases,
)
from .utils import (
    AnymailTestMixin,
    sample_image_content,
)


@tag("forwardemail")
@override_settings(
    EMAIL_BACKEND="anymail.backends.forwardemail.EmailBackend",
    ANYMAIL={
        "FORWARDEMAIL_API_KEY": "test_api_key",
    },
)
class ForwardEmailBackendMockAPITestCase(RequestsBackendMockAPITestCase):
    DEFAULT_RAW_RESPONSE = (
        b'{"id": "5f1f3c...", "message_id": "<abc123@forwardemail.net>",'
        b' "status": "queued"}'
    )

    def setUp(self):
        super().setUp()
        # Simple message useful for many tests
        self.message = mail.EmailMultiAlternatives(
            "Subject", "Text Body", "from@example.com", ["to@example.com"]
        )


@tag("forwardemail")
class ForwardEmailBackendStandardEmailTests(ForwardEmailBackendMockAPITestCase):
    """Test backend support for Django standard email features"""

    def test_send_mail(self):
        """Test basic API for simple send"""
        mail.send_mail(
            "Subject here",
            "Here is the message.",
            "from@sender.example.com",
            ["to@example.com"],
            fail_silently=False,
        )
        self.assert_esp_called("/v1/emails")
        auth = self.get_api_call_auth()
        # HTTP Basic auth: API key as username, empty password
        self.assertEqual(auth, ("test_api_key", ""))
        data = self.get_api_call_json()
        self.assertEqual(data["subject"], "Subject here")
        self.assertEqual(data["text"], "Here is the message.")
        self.assertEqual(data["from"], "from@sender.example.com")
        self.assertEqual(data["to"], "to@example.com")

    def test_name_addr(self):
        """Make sure RFC2822 name-addr format (with display-name) is allowed"""
        msg = mail.EmailMessage(
            "Subject",
            "Message",
            "From Name <from@example.com>",
            ["Recipient #1 <to1@example.com>", "to2@example.com"],
            cc=["Carbon Copy <cc1@example.com>", "cc2@example.com"],
            bcc=["Blind Copy <bcc1@example.com>", "bcc2@example.com"],
        )
        msg.send()
        data = self.get_api_call_json()
        self.assertEqual(data["from"], "From Name <from@example.com>")
        self.assertEqual(data["to"], "Recipient #1 <to1@example.com>, to2@example.com")
        self.assertEqual(data["cc"], "Carbon Copy <cc1@example.com>, cc2@example.com")
        self.assertEqual(data["bcc"], "Blind Copy <bcc1@example.com>, bcc2@example.com")

    def test_email_message(self):
        email = mail.EmailMessage(
            "Subject",
            "Body goes here",
            "from@example.com",
            ["to1@example.com", "Also To <to2@example.com>"],
            cc=["cc1@example.com", "Also CC <cc2@example.com>"],
            reply_to=["another@example.com", "Other <reply2@example.com>"],
            headers={
                "X-MyHeader": "my value",
                "Message-ID": "mycustommsgid@example.com",
            },
        )
        email.send()
        data = self.get_api_call_json()
        self.assertEqual(data["subject"], "Subject")
        self.assertEqual(data["text"], "Body goes here")
        self.assertEqual(data["from"], "from@example.com")
        self.assertEqual(data["to"], "to1@example.com, Also To <to2@example.com>")
        self.assertEqual(data["cc"], "cc1@example.com, Also CC <cc2@example.com>")
        self.assertEqual(
            data["replyTo"], "another@example.com, Other <reply2@example.com>"
        )
        self.assertEqual(data["headers"]["X-MyHeader"], "my value")
        self.assertEqual(data["headers"]["Message-ID"], "mycustommsgid@example.com")

    def test_html_message(self):
        text_content = "This is an important message."
        html_content = "<p>This is an <strong>important</strong> message.</p>"
        email = mail.EmailMultiAlternatives(
            "Subject", text_content, "from@example.com", ["to@example.com"]
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
        data = self.get_api_call_json()
        self.assertEqual(data["text"], text_content)
        self.assertEqual(data["html"], html_content)

    def test_html_only_message(self):
        html_content = "<p>This is an <strong>important</strong> message.</p>"
        email = mail.EmailMessage(
            "Subject", html_content, "from@example.com", ["to@example.com"]
        )
        email.content_subtype = "html"
        email.send()
        data = self.get_api_call_json()
        self.assertNotIn("text", data)
        self.assertEqual(data["html"], html_content)

    def test_extra_headers_serialize_int(self):
        self.message.extra_headers = {"X-Num": 3}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["headers"]["X-Num"], "3")

    def test_attachments(self):
        email = mail.EmailMessage(
            "Subject", "Body", "from@example.com", ["to@example.com"]
        )
        email.attach("test.txt", "test content", "text/plain")
        email.attach("data.csv", b"id,name\n1,amy", "text/csv")
        email.send()
        data = self.get_api_call_json()
        attachments = data["attachments"]
        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[0]["filename"], "test.txt")
        self.assertEqual(attachments[0]["contentType"], 'text/plain; charset="utf-8"')
        self.assertEqual(attachments[0]["encoding"], "base64")
        self.assertEqual(b64decode(attachments[0]["content"]), b"test content")
        self.assertEqual(attachments[1]["filename"], "data.csv")
        self.assertEqual(b64decode(attachments[1]["content"]), b"id,name\n1,amy")

    def test_inline_image(self):
        image_data = sample_image_content()
        cid = attach_inline_image(self.message, image_data)
        html = '<img src="cid:%s">' % cid
        self.message.attach_alternative(html, "text/html")
        self.message.send()
        data = self.get_api_call_json()
        attachments = data["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["cid"], cid)
        self.assertEqual(attachments[0]["contentDisposition"], "inline")
        self.assertEqual(b64decode(attachments[0]["content"]), image_data)

    def test_api_failure(self):
        self.set_mock_response(status_code=400, raw=b'{"message": "Bad request"}')
        with self.assertRaisesMessage(AnymailAPIError, "Bad request"):
            self.message.send()

    def test_api_failure_fail_silently(self):
        self.set_mock_response(status_code=400)
        sent = self.message.send(fail_silently=True)
        self.assertEqual(sent, 0)


@tag("forwardemail")
class ForwardEmailBackendAnymailFeatureTests(ForwardEmailBackendMockAPITestCase):
    """Test backend support for Anymail added features"""

    def test_envelope_sender_unsupported(self):
        # Forward Email manages the SMTP envelope itself and does not expose
        # Nodemailer's envelope option, so envelope_sender can't be honored.
        self.message.envelope_sender = "bounce@example.com"
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "envelope_sender"):
            self.message.send()

    def test_metadata(self):
        self.message.metadata = {"user_id": "123", "items": 6}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            json.loads(data["headers"]["X-Metadata"]),
            {"user_id": "123", "items": 6},
        )

    def test_tags(self):
        self.message.tags = ["receipt", "reorder test 12"]
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(
            json.loads(data["headers"]["X-Tags"]), ["receipt", "reorder test 12"]
        )

    def test_send_at(self):
        # Forward Email schedules delivery by the message `date`.
        utc_plus_6 = get_fixed_timezone(6 * 60)
        with override_current_timezone(utc_plus_6):
            self.message.send_at = datetime(
                2022, 10, 11, 12, 13, 14, 567000, tzinfo=utc_plus_6
            )
            self.message.send()
            data = self.get_api_call_json()
            self.assertEqual(data["date"], "2022-10-11T12:13:14.567000+06:00")

    def test_esp_extra(self):
        self.message.esp_extra = {"priority": "high", "icalEvent": {"content": "..."}}
        self.message.send()
        data = self.get_api_call_json()
        self.assertEqual(data["priority"], "high")
        self.assertEqual(data["icalEvent"], {"content": "..."})

    def test_default_omits_options(self):
        """Make sure by default we don't send any ESP-specific options"""
        self.message.send()
        data = self.get_api_call_json()
        self.assertNotIn("sender", data)
        self.assertNotIn("date", data)
        self.assertNotIn("attachments", data)
        self.assertNotIn("headers", data)

    def test_tracking_unsupported(self):
        self.message.track_clicks = True
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "track_clicks"):
            self.message.send()
        self.message.track_clicks = None
        self.message.track_opens = True
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "track_opens"):
            self.message.send()

    def test_template_id_unsupported(self):
        self.message.template_id = "welcome"
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "template_id"):
            self.message.send()

    def test_merge_data_unsupported(self):
        self.message.to = ["to1@example.com", "to2@example.com"]
        self.message.merge_data = {}
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "merge_data"):
            self.message.send()

    def test_merge_global_data_unsupported(self):
        self.message.merge_global_data = {"greeting": "Hi"}
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "merge_global_data"):
            self.message.send()

    def test_merge_metadata_unsupported(self):
        self.message.to = ["to1@example.com", "to2@example.com"]
        self.message.merge_metadata = {"to1@example.com": {"x": 1}}
        with self.assertRaisesMessage(AnymailUnsupportedFeature, "merge_metadata"):
            self.message.send()

    def test_send_status(self):
        # Anymail's message_id is Forward Email's internal record id (its `id`),
        # which is the value its bounce webhooks reference as `email_id`.
        msg = AnymailMessage("Subject", "Body", "from@example.com", ["to@example.com"])
        sent = msg.send()
        self.assertEqual(sent, 1)
        self.assertEqual(msg.anymail_status.status, {"queued"})
        self.assertEqual(msg.anymail_status.message_id, "5f1f3c...")
        recipient = msg.anymail_status.recipients["to@example.com"]
        self.assertEqual(recipient.status, "queued")
        self.assertEqual(recipient.message_id, "5f1f3c...")

    def test_success_response_without_id(self):
        # A 2xx response means the message was accepted, so a missing id must
        # not be reported as a send failure (message_id is simply None).
        self.set_mock_response(raw=b'{"message": "OK", "statusCode": 200}')
        msg = AnymailMessage("Subject", "Body", "from@example.com", ["to@example.com"])
        sent = msg.send()
        self.assertEqual(sent, 1)
        self.assertEqual(msg.anymail_status.status, {"queued"})
        self.assertIsNone(msg.anymail_status.message_id)

    def test_non_dict_api_response(self):
        # A non-dict response (list/str/None) must not crash with AttributeError;
        # it should be converted to an AnymailRequestsAPIError (respecting
        # fail_silently). See parse_recipient_status.
        self.set_mock_response(raw=b"[]")
        with self.assertRaisesMessage(
            AnymailAPIError, "Invalid Forward Email API response format"
        ):
            self.message.send()


@tag("forwardemail")
@override_settings(EMAIL_BACKEND="anymail.backends.forwardemail.EmailBackend")
class ForwardEmailBackendConfigurationTests(AnymailTestMixin, SimpleTestCase):
    """Test various configuration options"""

    def test_missing_api_key(self):
        from django.core.exceptions import ImproperlyConfigured

        with self.assertRaises(ImproperlyConfigured) as cm:
            mail.send_mail("Subject", "Body", "from@example.com", ["to@example.com"])
        self.assertRegex(str(cm.exception), r"\bFORWARDEMAIL_API_KEY\b")

    @override_settings(
        ANYMAIL={
            "FORWARDEMAIL_API_KEY": "test_api_key",
            "FORWARDEMAIL_API_URL": "https://example.com/custom/v9",
        }
    )
    def test_api_url_override(self):
        """A custom api_url is honored, and a trailing slash is added if missing"""
        from anymail.backends.forwardemail import EmailBackend

        backend = EmailBackend()
        self.assertEqual(backend.api_url, "https://example.com/custom/v9/")


@tag("forwardemail")
@override_settings(
    EMAIL_BACKEND="anymail.backends.forwardemail.EmailBackend",
    ANYMAIL={"FORWARDEMAIL_API_KEY": "test_api_key"},
)
class ForwardEmailBackendSessionSharingTestCase(SessionSharingTestCases):
    """Requests session sharing tests"""

    DEFAULT_RAW_RESPONSE = (
        b'{"id": "5f1f3c", "message_id": "<m@forwardemail.net>", "status": "queued"}'
    )
