import os
import unittest
from email.utils import formataddr

from django.test import SimpleTestCase, override_settings, tag

from anymail.exceptions import AnymailAPIError
from anymail.message import AnymailMessage

from .utils import AnymailTestMixin

ANYMAIL_TEST_FORWARDEMAIL_API_KEY = os.getenv("ANYMAIL_TEST_FORWARDEMAIL_API_KEY")
ANYMAIL_TEST_FORWARDEMAIL_DOMAIN = os.getenv("ANYMAIL_TEST_FORWARDEMAIL_DOMAIN")


@tag("forwardemail", "live")
@unittest.skipUnless(
    ANYMAIL_TEST_FORWARDEMAIL_API_KEY and ANYMAIL_TEST_FORWARDEMAIL_DOMAIN,
    "Set ANYMAIL_TEST_FORWARDEMAIL_API_KEY and ANYMAIL_TEST_FORWARDEMAIL_DOMAIN "
    "environment variables to run Forward Email integration tests",
)
@override_settings(
    ANYMAIL_FORWARDEMAIL_API_KEY=ANYMAIL_TEST_FORWARDEMAIL_API_KEY,
    EMAIL_BACKEND="anymail.backends.forwardemail.EmailBackend",
)
class ForwardEmailBackendIntegrationTests(AnymailTestMixin, SimpleTestCase):
    """Forward Email API integration tests

    These tests run against the **live** Forward Email API, using the environment
    variable ``ANYMAIL_TEST_FORWARDEMAIL_API_KEY`` as the API key and
    ``ANYMAIL_TEST_FORWARDEMAIL_DOMAIN`` to construct sender addresses. If those
    variables are not set, these tests won't run.

    Forward Email only allows sending from a verified domain/alias.
    """

    def setUp(self):
        super().setUp()
        self.from_email = "test@%s" % ANYMAIL_TEST_FORWARDEMAIL_DOMAIN
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
        self.assertGreater(len(message_id), 0)
        self.assertEqual(anymail_status.status, {sent_status})
        self.assertEqual(anymail_status.message_id, message_id)

    def test_all_options(self):
        message = AnymailMessage(
            subject="Anymail Forward Email all-options integration test",
            body="This is the text body",
            from_email=formataddr(("Test From, comma", self.from_email)),
            to=["test+to1@anymail.dev", '"Recipient 2, OK?" <test+to2@anymail.dev>'],
            cc=["test+cc1@anymail.dev", "Copy 2 <test+cc2@anymail.dev>"],
            reply_to=['"Reply, comma" <reply@example.com>', "reply2@example.com"],
            headers={"X-Anymail-Test": "value", "X-Anymail-Count": 3},
            metadata={"meta1": "simple string", "meta2": 2},
            tags=["tag 1", "tag 2"],
        )
        message.attach_alternative("<p>HTML content</p>", "text/html")
        message.attach("attachment1.txt", "Here is some\ntext", "text/plain")

        message.send()
        self.assertEqual(message.anymail_status.status, {"queued"})
        self.assertGreater(len(message.anymail_status.message_id), 0)

    @override_settings(ANYMAIL_FORWARDEMAIL_API_KEY="Hey, that's not an API key!")
    def test_invalid_api_key(self):
        with self.assertRaises(AnymailAPIError) as cm:
            self.message.send()
        self.assertIn(cm.exception.status_code, (401, 403))
