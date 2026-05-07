"""
AutoSecOps — Slack Notifier
Sends scan result notifications to Slack webhooks.
"""

import urllib.request
import json
import os
from typing import Any

SLACK_API = "https://hooks.slack.com/services/"


class SlackNotifier:
    """
    Send messages to Slack via Incoming Webhook.
    """

    def __init__(self, webhook: str | None = None):
        self.webhook = os.environ.get("SLACK_WEBHOOK") or webhook

    def _send(self, payload: dict[str, Any]) -> bool:
        if not self.webhook:
            print("[slack] warn: no webhook configured, skipping")
            return False
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read() == b"ok"
        except Exception as e:
            print(f"[slack] warn: failed to send: {e}")
            return False

    def send_text(self, text: str, username: str = "AutoSecOps") -> bool:
        return self._send({
            "username": username,
            "text": text,
        })

    def send_blocks(self, blocks: list[dict]) -> bool:
        return self._send({"blocks": blocks})

    def send_scan_result(
        self,
        scan_id: str,
        target: str,
        status: str,
        summary: dict[str, Any],
        webhook: str | None = None,
    ) -> bool:
        if webhook:
            original_webhook = self.webhook
            self.webhook = webhook

        sev = summary or {}
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        medium = sev.get("medium", 0)
        low = sev.get("low", 0)
        total = sev.get("total", 0)

        color = "#f85149" if critical > 0 else ("#d29922" if high > 0 else "#3fb950")
        status_emoji = "🔴" if critical > 0 else ("🟠" if high > 0 else ("🟡" if medium > 0 else "✅"))

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{status_emoji} AutoSecOps Scan Report"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status_emoji} {status}"},
                    {"type": "mrkdwn", "text": f"*Total:*\n{total}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*🔴 Critical:*\n{critical}"},
                    {"type": "mrkdwn", "text": f"*🟠 High:*\n{high}"},
                    {"type": "mrkdwn", "text": f"*🟡 Medium:*\n{medium}"},
                    {"type": "mrkdwn", "text": f"*🟢 Low:*\n{low}"},
                ],
            },
        ]

        result = self._send({
            "attachments": [{"color": color, "blocks": blocks}]
        })

        if webhook:
            self.webhook = original_webhook

        return result


def main():
    notifier = SlackNotifier()
    notifier.send_scan_result(
        scan_id="abc12345",
        target="./my-project",
        status="completed",
        summary={"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
    )


if __name__ == "__main__":
    main()
