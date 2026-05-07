"""
AutoSecOps — DingTalk Notifier
Sends scan result notifications to DingTalk robot webhooks.
Supports text messages and Markdown-formatted card messages.
"""

import hashlib
import hmac
import time
import urllib.request
import json
import os
from typing import Any

DINGTALK_API = "https://oapi.dingtalk.com/robot/send"


class DingTalkNotifier:
    """
    Send messages to a DingTalk group via custom robot webhook.
    Supports both text and Markdown message types.
    """

    def __init__(self, webhook: str | None = None, secret: str | None = None):
        self.webhook = os.environ.get("DINGTALK_WEBHOOK") or webhook
        self.secret = (os.environ.get("DINGTALK_SECRET") or secret or "").strip()

    def _sign(self) -> str:
        """Generate HMAC-SHA256 signature for DingTalk robot security."""
        if not self.secret:
            return ""
        timestamp = str(int(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{self.secret}"
        hashed = hmac.new(
            self.secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(hashed.decode("utf-8"))
        return f"&timestamp={timestamp}&sign={sign}"

    def _send(self, payload: dict[str, Any]) -> bool:
        if not self.webhook:
            print("[dingtalk] warn: no webhook configured, skipping")
            return False

        url = self.webhook + self._sign() if self.secret else self.webhook
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get("errcode") == 0:
                    return True
                print(f"[dingtalk] error: {result.get('errmsg', 'unknown')}")
                return False
        except Exception as e:
            print(f"[dingtalk] warn: failed to send: {e}")
            return False

    def send_text(self, content: str) -> bool:
        """Send a plain text message."""
        return self._send({
            "msgtype": "text",
            "text": {"content": content},
        })

    def send_markdown(self, title: str, text: str) -> bool:
        """Send a Markdown-formatted message."""
        return self._send({
            "msgtype": "markdown",
            "markdown": {"title": title, "text": text},
        })

    def send_scan_result(
        self,
        scan_id: str,
        target: str,
        status: str,
        summary: dict[str, Any],
        webhook: str | None = None,
    ) -> bool:
        """
        Format scan results as a DingTalk Markdown card and send.
        summary keys: total, critical, high, medium, low
        """
        if webhook:
            original_webhook = self.webhook
            self.webhook = webhook
            # Temporarily override webhook for this call

        sev = summary or {}
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        medium = sev.get("medium", 0)
        low = sev.get("low", 0)
        total = sev.get("total", 0)

        # Severity emoji
        if critical > 0:
            sev_emoji = "🔴 CRITICAL"
        elif high > 0:
            sev_emoji = "🟠 HIGH"
        elif medium > 0:
            sev_emoji = "🟡 MEDIUM"
        else:
            sev_emoji = "✅ PASS"

        md_text = (
            f"## 🛡️ AutoSecOps 扫描报告\n\n"
            f"**扫描ID**: `{scan_id}`\n"
            f"**目标**: `{target}`\n"
            f"**状态**: {sev_emoji}\n\n"
            f"### 漏洞统计\n\n"
            f"- 🔴 Critical: **{critical}**\n"
            f"- 🟠 High: **{high}**\n"
            f"- 🟡 Medium: **{medium}**\n"
            f"- 🟢 Low: **{low}**\n"
            f"- 📊 Total: **{total}**\n\n"
            f"> 查看完整报告 → [AutoSecOps Web UI](http://localhost:8080/report/{scan_id})"
        )

        # Restore webhook if temporarily overridden
        if webhook:
            self.webhook = original_webhook

        return self.send_markdown(f"AutoSecOps 扫描报告 — {sev_emoji}", md_text)


def main():
    notifier = DingTalkNotifier()
    # Example
    notifier.send_scan_result(
        scan_id="abc12345",
        target="./my-project",
        status="completed",
        summary={"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
    )


if __name__ == "__main__":
    main()
