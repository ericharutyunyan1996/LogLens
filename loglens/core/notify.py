"""Deliver a text to a chat webhook (Slack, Teams, any JSON endpoint) or by e-mail.

Passwords are never stored by LogLens: an SMTP password comes from the ``LOGLENS_SMTP_PASSWORD`` environment variable
(or is empty for relays that need none). Messages go out as given: mask secrets before calling.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from urllib.parse import urlparse

TIMEOUT_S = 20.0
MAX_MESSAGE_CHARS = 28_000  # under the limits of Teams / Slack webhooks


class DeliveryError(Exception):
    """A delivery failed; the message says why in plain words."""


@dataclass(frozen=True, slots=True)
class MailSettings:
    host: str
    port: int = 587
    sender: str = ""
    recipients: tuple[str, ...] = ()
    user: str = ""
    starttls: bool = True


def _trim(text: str) -> str:
    return text if len(text) <= MAX_MESSAGE_CHARS else text[: MAX_MESSAGE_CHARS - 20] + "\n… (shortened)"


def post_webhook(url: str, text: str, *, title: str = "") -> None:
    """POST ``{"text": …}`` (accepted by Slack, Teams workflows, Mattermost and most JSON hooks)."""
    parsed = urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise DeliveryError("The webhook address must start with https:// (http is only allowed for localhost).")
    body = json.dumps({"text": _trim(f"{title}\n\n{text}" if title else text)}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            if response.status >= 300:
                raise DeliveryError(f"The webhook answered {response.status}.")
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"The webhook refused the message ({exc.code} {exc.reason}).") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DeliveryError(f"The webhook could not be reached: {getattr(exc, 'reason', exc)}.") from exc


def send_mail(settings: MailSettings, subject: str, text: str) -> None:
    if not settings.host or not settings.recipients or not settings.sender:
        raise DeliveryError("E-mail needs a server, a sender and at least one recipient.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    message.set_content(_trim(text))
    password = os.environ.get("LOGLENS_SMTP_PASSWORD", "")
    try:
        with smtplib.SMTP(settings.host, settings.port, timeout=TIMEOUT_S) as smtp:
            if settings.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if settings.user:
                smtp.login(settings.user, password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"The e-mail could not be sent: {exc}") from exc
