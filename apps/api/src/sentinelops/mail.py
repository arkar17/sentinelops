"""Platform transactional email (FR-ID-007) through the configured SMTP relay.

Message bodies can contain single-use links, so they are never logged.
"""

import asyncio
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage as MimeMessage
from typing import Protocol

from sentinelops.config import Settings
from sentinelops.errors import AppError


@dataclass(frozen=True)
class OutgoingEmail:
    to: str
    subject: str
    body: str


class Mailer(Protocol):
    async def send(self, message: OutgoingEmail) -> None: ...


class MailDeliveryError(AppError):
    """``permanent`` marks rejections a retry cannot fix (recipient refused, 5xx reply)."""

    def __init__(self, *, permanent: bool = False) -> None:
        super().__init__(502, "MAIL_DELIVERY_FAILED", "The email could not be sent")
        self.permanent = permanent


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _send_sync(self, message: OutgoingEmail) -> None:
        settings = self._settings
        if settings.smtp_host is None:
            raise MailDeliveryError
        mime = MimeMessage()
        mime["From"] = settings.smtp_from
        mime["To"] = message.to
        mime["Subject"] = message.subject
        mime.set_content(message.body)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(mime)

    async def send(self, message: OutgoingEmail) -> None:
        try:
            await asyncio.to_thread(self._send_sync, message)
        except MailDeliveryError:
            raise
        except smtplib.SMTPRecipientsRefused as exc:
            raise MailDeliveryError(permanent=True) from exc
        except smtplib.SMTPResponseException as exc:
            raise MailDeliveryError(permanent=exc.smtp_code >= 500) from exc
        except (OSError, smtplib.SMTPException) as exc:
            raise MailDeliveryError from exc
