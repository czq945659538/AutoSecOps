"""
AutoSecOps — Email Notifier
Sends scan result notifications via SMTP email.
"""

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

class EmailNotifier:
    """
    Send email notifications using SMTP (SSL/TLS).
    """

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int = 465,
        username: str | None = None,
        password: str | None = None,
        from_addr: str | None = None,
        to_addrs: list[str] | None = None,
        use_tls: bool = True,
    ):
        self.smtp_host = os.environ.get("SMTP_HOST") or smtp_host
        self.smtp_port = int(os.environ.get("SMTP_PORT") or smtp_port)
        self.username = os.environ.get("SMTP_USERNAME") or username
        self.password = os.environ.get("SMTP_PASSWORD") or password
        self.from_addr = os.environ.get("EMAIL_FROM") or from_addr
        self.to_addrs = (os.environ.get("EMAIL_TO") or "").split(",") if not to_addrs else to_addrs
        self.use_tls = use_tls

    def send(
        self,
        subject: str,
        body_text: str,
        body_html: str = "",
        to_addrs: list[str] | None = None,
    ) -> bool:
        if not self.smtp_host or not self.username or not self.password:
            print("[email] warn: SMTP not configured, skipping")
            return False

        to = to_addrs or self.to_addrs
        if not to:
            print("[email] warn: no recipients configured")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr or self.username
        msg["To"] = ", ".join(to)

        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            msg.attach(MIMEText(body_html, "html", "utf-8"))

        try:
            if self.smtp_port == 465:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=ctx) as server:
                    server.login(self.username, self.password)
                    server.sendmail(self.from_addr or self.username, to, msg.as_string())
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls()
                    server.login(self.username, self.password)
                    server.sendmail(self.from_addr or self.username, to, msg.as_string())
            return True
        except Exception as e:
            print(f"[email] warn: failed to send: {e}")
            return False

    def send_scan_result(
        self,
        scan_id: str,
        target: str,
        status: str,
        summary: dict[str, Any],
    ) -> bool:
        sev = summary or {}
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        medium = sev.get("medium", 0)
        low = sev.get("low", 0)
        total = sev.get("total", 0)

        severity = "🔴 CRITICAL" if critical > 0 else ("🟠 HIGH" if high > 0 else "✅ PASS")

        subject = f"[AutoSecOps] Scan {status.upper()} — {severity} ({total} findings)"

        text = (
            f"AutoSecOps Security Scan Report\n\n"
            f"Scan ID   : {scan_id}\n"
            f"Target    : {target}\n"
            f"Status    : {status}\n"
            f"Total     : {total}\n"
            f"Critical  : {critical}\n"
            f"High      : {high}\n"
            f"Medium    : {medium}\n"
            f"Low       : {low}\n\n"
            f"View report: http://localhost:8080/report/{scan_id}"
        )

        html = f"""
        <html><body style="font-family: Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 20px;">
          <h2>🛡️ AutoSecOps — Scan Report</h2>
          <table style="border-collapse: collapse; width: 100%; max-width: 500px;">
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Scan ID</strong></td><td style="padding: 8px; border: 1px solid #30363d;"><code>{scan_id}</code></td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Target</strong></td><td style="padding: 8px; border: 1px solid #30363d;"><code>{target}</code></td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Status</strong></td><td style="padding: 8px; border: 1px solid #30363d;">{severity}</td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Critical</strong></td><td style="padding: 8px; border: 1px solid #30363d; color: #f85149;">{critical}</td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>High</strong></td><td style="padding: 8px; border: 1px solid #30363d; color: #d29922;">{high}</td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Medium</strong></td><td style="padding: 8px; border: 1px solid #30363d; color: #e3b341;">{medium}</td></tr>
            <tr><td style="padding: 8px; border: 1px solid #30363d;"><strong>Low</strong></td><td style="padding: 8px; border: 1px solid #30363d; color: #3fb950;">{low}</td></tr>
          </table>
          <p style="margin-top: 20px;"><a href="http://localhost:8080/report/{scan_id}" style="color: #58a6ff;">View Full Report →</a></p>
        </body></html>
        """

        return self.send(subject, text, html)


def main():
    notifier = EmailNotifier()
    notifier.send_scan_result(
        scan_id="abc12345",
        target="./my-project",
        status="completed",
        summary={"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
    )


if __name__ == "__main__":
    main()
