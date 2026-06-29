.. _forwardemail-backend:

Forward Email
=============

Anymail integrates Django with the `Forward Email`_ service, using their
`email sending API`_ and their webhook support for status tracking and
inbound email.

.. versionadded:: 15.1

.. _Forward Email: https://forwardemail.net/
.. _email sending API: https://forwardemail.net/en/email-api#outbound-emails


Settings
--------

.. rubric:: EMAIL_BACKEND

To use Anymail's Forward Email backend, set:

  .. code-block:: python

      EMAIL_BACKEND = "anymail.backends.forwardemail.EmailBackend"

in your settings.py.


.. setting:: ANYMAIL_FORWARDEMAIL_API_KEY

.. rubric:: FORWARDEMAIL_API_KEY

Required for sending. An API token from your Forward Email
`My Account → Security`_ page (or an alias-specific generated password).
Forward Email authenticates the sending API using HTTP Basic auth with
the token as the username and an empty password; Anymail handles this for you.

  .. code-block:: python

      ANYMAIL = {
          ...
          "FORWARDEMAIL_API_KEY": "...",
      }

Anymail will also look for ``FORWARDEMAIL_API_KEY`` at the root of the settings
file if neither ``ANYMAIL["FORWARDEMAIL_API_KEY"]`` nor
``ANYMAIL_FORWARDEMAIL_API_KEY`` is set.

.. _My Account → Security: https://forwardemail.net/en/my-account/security


.. setting:: ANYMAIL_FORWARDEMAIL_WEBHOOK_SIGNING_KEY

.. rubric:: FORWARDEMAIL_WEBHOOK_SIGNING_KEY

The "Webhook Signature Payload Verification Key" for your Forward Email domain,
used to verify that webhook posts (both status tracking and inbound) actually
came from Forward Email. Recommended if you are using Anymail's webhooks.

Find this in your Forward Email domain settings (My Account → Domains →
Settings → "Webhook Signature Payload Verification Key"). You can rotate
this key at any time.

  .. code-block:: python

      ANYMAIL = {
          ...
          "FORWARDEMAIL_WEBHOOK_SIGNING_KEY": "...",
      }

This is separate from Anymail's
:setting:`WEBHOOK_SECRET <ANYMAIL_WEBHOOK_SECRET>` setting. You can secure
Forward Email's webhooks with the signing key, with Anymail's shared secret,
or both. See :ref:`forwardemail-webhooks` below.


.. setting:: ANYMAIL_FORWARDEMAIL_API_URL

.. rubric:: FORWARDEMAIL_API_URL

The base url for calling the Forward Email API.

The default is ``FORWARDEMAIL_API_URL = "https://api.forwardemail.net/v1/"``.
(It's unlikely you would need to change this.)


.. _forwardemail-quirks:

Limitations and quirks
----------------------

Forward Email is a privacy-focused service that intentionally does not
offer many of the tracking and marketing features of other ESPs.

Anymail normally raises an :exc:`~anymail.exceptions.AnymailUnsupportedFeature`
error when you try to send a message using features that Forward Email doesn't
support. You can tell Anymail to suppress these errors and send the messages
anyway---see :ref:`unsupported-features`.

**No open or click tracking**
  Forward Email does not track message opens or clicks, so it does not support
  Anymail's :attr:`~anymail.message.AnymailMessage.track_clicks` or
  :attr:`~anymail.message.AnymailMessage.track_opens`.

**No ESP templates or batch sending**
  Forward Email does not offer :ref:`ESP stored templates <esp-stored-templates>`
  or a batch-sending API, so it does not support Anymail's
  :attr:`~anymail.message.AnymailMessage.template_id`,
  :attr:`~anymail.message.AnymailMessage.merge_data`,
  :attr:`~anymail.message.AnymailMessage.merge_global_data`,
  :attr:`~anymail.message.AnymailMessage.merge_metadata`, or
  :attr:`~anymail.message.AnymailMessage.merge_headers`.

**Tags and metadata are exposed to the recipient**
  Anymail implements its normalized
  :attr:`~anymail.message.AnymailMessage.tags` and
  :attr:`~anymail.message.AnymailMessage.metadata` features for Forward Email
  using custom ``X-Tags`` and ``X-Metadata`` email headers. That means they can
  be visible to recipients via their email app's "show original message" (or
  similar) command. **Do not include sensitive data in tags or metadata.**
  Because Forward Email does not echo these headers back in its webhooks,
  tags and metadata are not reported with tracking events.

**No envelope sender**
  Forward Email manages the SMTP envelope itself and does not expose a way to
  override the envelope (Return-Path) sender, so it does not support Anymail's
  :attr:`~anymail.message.AnymailMessage.envelope_sender`.

**No scheduled delivery (send_at)**
  Forward Email's API has a ``date`` field, but that only sets the message
  :mailheader:`Date` header---it is not a verified scheduled-delivery control.
  To avoid silently sending immediately when a caller expects delayed delivery,
  Anymail does not support :attr:`~anymail.message.AnymailMessage.send_at` for
  Forward Email. (If you only want to set a future :mailheader:`Date` header,
  you can pass ``date`` via :ref:`esp_extra <forwardemail-esp-extra>`.)

**Status tracking is limited to delivery failures**
  Forward Email's tracking webhook reports *bounce* (delivery failure) events
  only. Anymail will report these as
  :attr:`~anymail.signals.AnymailTrackingEvent.event_type` of ``bounced``
  (hard failures) or ``deferred`` (soft/temporary failures).


.. _forwardemail-esp-extra:

esp_extra support
-----------------

Anymail's Forward Email backend will pass
:attr:`~anymail.message.AnymailMessage.esp_extra` values directly to Forward
Email's `email sending API`_ (which is modeled on `Nodemailer`_ message
options). This lets you use Forward Email features that aren't part of
Anymail's normalized API. Example:

  .. code-block:: python

      message = AnymailMessage(...)
      message.esp_extra = {
          "priority": "high",
          # send an attached calendar event:
          "icalEvent": {"content": "BEGIN:VCALENDAR..."},
      }

.. _Nodemailer: https://nodemailer.com/message/


.. _forwardemail-webhooks:

Status tracking and inbound webhooks
------------------------------------

Anymail's normalized :ref:`status tracking <event-tracking>` and
:ref:`inbound <inbound>` handling both work with Forward Email's webhooks.

Forward Email signs every webhook post with an ``X-Webhook-Signature`` header
(an HMAC-SHA256 of the request body). To verify these signatures, set
:setting:`FORWARDEMAIL_WEBHOOK_SIGNING_KEY
<ANYMAIL_FORWARDEMAIL_WEBHOOK_SIGNING_KEY>` to your domain's "Webhook Signature
Payload Verification Key." You can secure the webhooks with this signing key,
with Anymail's shared :setting:`WEBHOOK_SECRET <ANYMAIL_WEBHOOK_SECRET>`, or
both. Signature validation is recommended.

.. rubric:: Status tracking (bounce) webhook

In your Forward Email domain settings (My Account → Domains → Settings →
"Bounce Webhook"), set the bounce webhook URL to:

    :samp:`https://{yoursite.example.com}/anymail/forwardemail/tracking/`

Or, if you are using Anymail's :setting:`WEBHOOK_SECRET
<ANYMAIL_WEBHOOK_SECRET>`, include the *random:random* shared secret:

    :samp:`https://{random}:{random}@{yoursite.example.com}/anymail/forwardemail/tracking/`

Forward Email will POST to this URL whenever an outbound message bounces.
Anymail reports these as ``bounced`` or ``deferred`` tracking events. The
event's :attr:`~anymail.signals.AnymailTrackingEvent.esp_event` is the parsed
Forward Email bounce payload.

.. rubric:: Inbound webhook

Forward Email can forward incoming mail for an alias to a webhook URL. Set the
alias's forwarding destination to your inbound URL (e.g., in a domain's alias
configuration or a ``forward-email`` DNS record):

    :samp:`https://{yoursite.example.com}/anymail/forwardemail/inbound/`

Or with Anymail's shared secret:

    :samp:`https://{random}:{random}@{yoursite.example.com}/anymail/forwardemail/inbound/`

Forward Email POSTs the full message (including raw MIME) to this URL. Anymail
parses it into an :class:`~anymail.inbound.AnymailInboundMessage` delivered with
the :data:`~anymail.signals.inbound` signal.
