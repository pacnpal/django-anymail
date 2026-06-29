import os
import unittest
from datetime import datetime, timedelta
from email.utils import formataddr

from django.test import SimpleTestCase, override_settings, tag

from anymail.exceptions import AnymailAPIError
from anymail.message import AnymailMessage

from .utils import AnymailTestMixin, sample_image_path

ANYMAIL_TEST_FORWARD_EMAIL_API_KEY = os.getenv("ANYMAIL_TEST_FORWARD_EMAIL_API_KEY")
ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN = os.getenv("ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN")


@tag("forward_email", "live")
@unittest.skipUnless(
    ANYMAIL_TEST_FORWARD_EMAIL_API_KEY and ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN,
    "Set ANYMAIL_TEST_FORWARD_EMAIL_API_KEY and ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN "
    "environment variables to run Forward Email integration tests",
)
@override_settings(
    ANYMAIL_FORWARD_EMAIL_API_KEY=ANYMAIL_TEST_FORWARD_EMAIL_API_KEY,
    EMAIL_BACKEND="anymail.backends.forward_email.EmailBackend",
)
class ForwardEmailBackendIntegrationTests(AnymailTestMixin, SimpleTestCase):
    """Forward Email API integration tests

    These tests run against the **live** Forward Email API, using the environment
    variable ``ANYMAIL_TEST_FORWARD_EMAIL_API_KEY`` as the API key and
    ``ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN`` to construct sender addresses. If those
    variables are not set, these tests won't run.

    Forward Email only allows sending from a verified domain/alias.
    """

    def setUp(self):
        super().setUp()
        self.from_email = "test@%s" % ANYMAIL_TEST_FORWARD_EMAIL_DOMAIN
        self.message = AnymailMessage(
            "Anymail Forward Email integration test",
            "Text content",
            self.from_email,
            ["test+to1@anymail.dev"],
        )
        self.message.attach_alternative("<p>HTML content</p>", "text/html")

    def test_simple_send(self):
        sent_count = self.message.send()
        self.assertEqual(sent_count, 1)

        anymail_status = self.message.anymail_status
        sent_status = anymail_status.recipients["test+to1@anymail.dev"].status
        message_id = anymail_status.recipients["test+to1@anymail.dev"].message_id

        self.assertEqual(sent_status, "queued")
        # Forward Email returns a record id, but tolerate None (a 2xx accept
        # without an id is still a successful send) rather than raising TypeError.
        self.assertTrue(message_id is None or len(message_id) > 0)
        self.assertEqual(anymail_status.status, {sent_status})
        self.assertEqual(anymail_status.message_id, message_id)

    def test_all_options(self):
        send_at = datetime.now() + timedelta(minutes=2)
        message = AnymailMessage(
            subject="Anymail Forward Email all-options integration test",
            body="This is the text body",
            # Verify workarounds for address formatting issues (non-ASCII
            # display name with a comma):
            from_email=formataddr(("Test «Från», med komma", self.from_email)),
            to=["test+to1@anymail.dev", '"Recipient 2, OK?" <test+to2@anymail.dev>'],
            cc=["test+cc1@anymail.dev", "Copy 2 <test+cc2@anymail.dev>"],
            bcc=["test+bcc1@anymail.dev", "Blind Copy 2 <test+bcc2@anymail.dev>"],
            reply_to=['"Reply, with comma" <reply@example.com>', "reply2@example.com"],
            headers={"X-Anymail-Test": "value", "X-Anymail-Count": 3},
            metadata={"meta1": "simple string", "meta2": 2},
            send_at=send_at,
            tags=["tag 1", "tag 2"],
        )
        message.attach("attachment1.txt", "Here is some\ntext", "text/plain")
        message.attach("attachment2.csv", "ID,Name\n1,Amy Lina", "text/csv")
        cid = message.attach_inline_image_file(sample_image_path())
        message.attach_alternative(
            "<p><b>HTML:</b> with <a href='http://example.com'>link</a>"
            " and image: <img src='cid:%s'></p>" % cid,
            "text/html",
        )
        message.attach_alternative(
            "<!doctype html><html amp4email><head><meta charset=utf-8>"
            "<style amp4email-boilerplate></style></head>"
            "<body>AMP content</body></html>",
            "text/x-amp-html",
        )

        message.send()
        # Forward Email always queues:
        self.assertEqual(message.anymail_status.status, {"queued"})
        message_id = message.anymail_status.message_id
        self.assertTrue(message_id is None or len(message_id) > 0)

    @override_settings(ANYMAIL_FORWARD_EMAIL_API_KEY="Hey, that's not an API key!")
    def test_invalid_api_key(self):
        with self.assertRaises(AnymailAPIError) as cm:
            self.message.send()
        self.assertIn(cm.exception.status_code, (401, 403))
