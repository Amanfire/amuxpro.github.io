"""Email sender for password reset and account verification."""
from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from backend.core.config import settings

logger = logging.getLogger(__name__)


def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
    subject   = "Reset your Amux Autoclicker Pro password"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;background:#060d1c;color:#e0e6f0;padding:32px;border-radius:12px;">
      <h2 style="color:#37d8ff;">🔒 Password Reset</h2>
      <p>We received a request to reset the password for your <strong>Amux Autoclicker Pro</strong> account.</p>
      <p>Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
      <a href="{reset_url}"
         style="display:inline-block;background:linear-gradient(90deg,#176bff,#7d4dff);
                color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;
                font-weight:bold;margin:16px 0;">
        Reset Password
      </a>
      <p style="color:#5c6f94;font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
      <hr style="border-color:#1a2d55;"/>
      <p style="color:#5c6f94;font-size:11px;">Amux Autoclicker Pro · <a href="{settings.FRONTEND_URL}" style="color:#37d8ff;">{settings.FRONTEND_URL}</a></p>
    </div>
    """
    return _send(to_email, subject, html)


def send_verification_email(to_email: str, token: str) -> bool:
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    subject    = "Verify your Amux account email"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;background:#060d1c;color:#e0e6f0;padding:32px;border-radius:12px;">
      <h2 style="color:#37d8ff;">✉️ Verify Your Email</h2>
      <p>Welcome to <strong>Amux Autoclicker Pro</strong>! Please verify your email to complete registration.</p>
      <a href="{verify_url}"
         style="display:inline-block;background:linear-gradient(90deg,#176bff,#7d4dff);
                color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0;">
        Verify Email
      </a>
      <p style="color:#5c6f94;font-size:12px;">This link expires in 24 hours.</p>
    </div>
    """
    return _send(to_email, subject, html)


def _send(to_email: str, subject: str, html_body: str) -> bool:
    if not settings.SMTP_USER:
        logger.warning("SMTP not configured — email not sent to %s", to_email)
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Amux <{settings.EMAIL_FROM}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to_email, msg.as_string())
        logger.info("Email sent to %s: %s", to_email, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False
