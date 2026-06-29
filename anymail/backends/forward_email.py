from ..exceptions import AnymailRequestsAPIError
from ..message import AnymailRecipientStatus
from ..utils import BASIC_NUMERIC_TYPES, get_anymail_setting
from .base_requests import AnymailRequestsBackend, RequestsPayload


class EmailBackend(AnymailRequestsBackend):
    """
    Forward Email (forwardemail.net) API Email Backend
    """

    esp_name = "Forward Email"

    def __init__(self, **kwargs):
        """Init options from Django settings"""
        esp_name = self.esp_name
        self.api_key = get_anymail_setting(
            "api_key", esp_name=esp_name, kwargs=kwargs, allow_bare=True
        )
        api_url = get_anymail_setting(
            "api_url",
            esp_name=esp_name,
            kwargs=kwargs,
            default="https://api.forwardemail.net/v1/",
        )
        if not api_url.endswith("/"):
            api_url += "/"
        super().__init__(api_url, **kwargs)

    def build_message_payload(self, message, defaults):
        return ForwardEmailPayload(message, defaults, self)

    def parse_recipient_status(self, response, payload, message):
        parsed_response = self.deserialize_json_response(response, payload, message)
        if not isinstance(parsed_response, dict):
            raise AnymailRequestsAPIError(
                "Invalid Forward Email API response format",
                email_message=message,
                payload=payload,
                response=response,
                backend=self,
            )

        # Use Forward Email's record id (the `email_id` its webhooks reference)
        # as the message_id; a 2xx response means the message was accepted, so
        # fall back gracefully if the id is missing.
        message_id = (
            parsed_response.get("id")
            or parsed_response.get("message_id")
            or parsed_response.get("messageId")
        )

        # Forward Email queues all messages for asynchronous delivery.
        return {
            recipient.addr_spec: AnymailRecipientStatus(
                message_id=message_id, status="queued"
            )
            for recipient in payload.recipients
        }


class ForwardEmailPayload(RequestsPayload):
    def __init__(self, message, defaults, backend, *args, **kwargs):
        self.recipients = []  # for parse_recipient_status
        headers = kwargs.pop("headers", {})
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        # Forward Email uses HTTP Basic auth: API token as username, no password.
        auth = (backend.api_key, "")
        super().__init__(
            message, defaults, backend, headers=headers, auth=auth, *args, **kwargs
        )

    def get_api_endpoint(self):
        return "emails"

    def init_payload(self):
        self.data = {}  # becomes json

    def serialize_data(self):
        return self.serialize_json(self.data)

    #
    # Payload construction
    #

    def set_from_email(self, email):
        self.data["from"] = email.format(idna_encode=self.backend.idna_encode)

    def set_recipients(self, recipient_type, emails):
        if emails:
            self.data[recipient_type] = ", ".join(
                email.format(idna_encode=self.backend.idna_encode) for email in emails
            )
            self.recipients += emails

    def set_subject(self, subject):
        self.data["subject"] = subject

    def set_reply_to(self, emails):
        if emails:
            # Nodemailer (Forward Email) accepts a comma-separated replyTo.
            self.data["replyTo"] = ", ".join(
                email.format(idna_encode=self.backend.idna_encode) for email in emails
            )

    def set_extra_headers(self, headers):
        # Forward Email requires header values to be strings.
        # Stringify ints and floats; anything else is the caller's responsibility.
        for key, value in headers.items():
            header_value = (
                str(value) if isinstance(value, BASIC_NUMERIC_TYPES) else value
            )
            # Message-ID and Date are protected headers in Nodemailer/Forward
            # Email: a value in the generic `headers` object is overwritten with
            # a generated one, so route them to their dedicated fields instead.
            if key.lower() == "message-id":
                self.data["messageId"] = header_value
            elif key.lower() == "date":
                self.data["date"] = header_value
            else:
                self.data.setdefault("headers", {})[key] = header_value

    def set_text_body(self, body):
        self.data["text"] = body

    def set_html_body(self, body):
        if "html" in self.data:
            # second html body could show up through multiple alternatives,
            # or html body + alternative
            self.unsupported_feature("multiple html parts")
        self.data["html"] = body

    def add_alternative(self, content, mimetype):
        # Forward Email (Nodemailer) supports an AMP alternative via `amp`.
        if mimetype.lower() == "text/x-amp-html":
            if "amp" in self.data:
                self.unsupported_feature("multiple amp parts")
            self.data["amp"] = content
        else:
            super().add_alternative(content, mimetype)

    def make_attachment(self, attachment):
        """Returns Forward Email (Nodemailer) attachment dict for attachment"""
        att = {
            "filename": attachment.name or "",
            "content": attachment.b64content,
            "encoding": "base64",
            "contentType": attachment.content_type,
        }
        if attachment.inline:
            att["cid"] = attachment.cid
            att["contentDisposition"] = "inline"
        return att

    def set_attachments(self, attachments):
        if attachments:
            self.data["attachments"] = [
                self.make_attachment(attachment) for attachment in attachments
            ]

    def set_metadata(self, metadata):
        # Forward Email has no native metadata; send as json in a custom header.
        self.data.setdefault("headers", {})["X-Metadata"] = self.serialize_json(
            metadata
        )

    def set_tags(self, tags):
        # Forward Email has no native tags; send as json in a custom header.
        self.data.setdefault("headers", {})["X-Tags"] = self.serialize_json(tags)

    def set_send_at(self, send_at):
        # Forward Email schedules delivery by the message `date`
        # (a future date, up to 30 days out, defers delivery).
        try:
            self.data["date"] = send_at.isoformat()
        except (AttributeError, TypeError):
            # User is responsible for formatting their own string
            self.data["date"] = send_at

    # Forward Email doesn't support open or click tracking.
    # def set_track_clicks(self, track_clicks):
    # def set_track_opens(self, track_opens):

    # Forward Email doesn't support server-side templates or batch/merge sending.
    # def set_template_id(self, template_id):
    # def set_merge_data(self, merge_data):

    # Forward Email manages the SMTP envelope itself, so envelope_sender is
    # unsupported. (Nodemailer's `sender` would only set an RFC Sender header.)
    # def set_envelope_sender(self, email):

    def set_esp_extra(self, extra):
        self.data.update(extra)
