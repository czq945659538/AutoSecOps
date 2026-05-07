"""
AutoSecOps — Feishu (Lark) Notifier
Sends scan result notifications to Feishu robot webhooks.
"""

import urllib.request
import json
import os
from typing import Any

FEISHU_API = "https://open.feishu.cn/open-apis/bot/v2/hook/"


class FeishuNotifier:
    """
    Send messages to a Feishu (Lark) group via custom robot webhook.
    """

    def __init__(self, webhook: str | None = None):
        self.webhook = os.environ.get("FEISHU_WEBHOOK") or webhook

    def _send(self, payload: dict[str, Any]) -> bool:
        if not self.webhook:
            print("[feishu] warn: no webhook configured, skipping")
            return False
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get("code") == 0 or result.get("StatusCode") == 0:
                    return True
                print(f"[feishu] error: {result}")
                return False
        except Exception as e:
            print(f"[feishu] warn: failed to send: {e}")
            return False

    def send_text(self, content: str) -> bool:
        return self._send({
            "msg_type": "text",
            "content": {"text": content},
        })

    def send_card(self, title: str, fields: list[dict], note: str = "") -> bool:
        """
        Send a rich Feishu interactive card.
        fields: [{"label": "...", "value": "..."}]
        """
        elements = []
        for f in fields:
            elements.append({
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**{f['label']}**: {f['value']}",
                },
            })
        if note:
            elements.append({"tag": "note", "elements": [{"tag": "plain_text", "content": note}]})

        payload = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": title},
                    "template": "red" if any("critical" in str(f).lower() for f in fields) else "blue",
                },
                "elements": elements,
            },
        }
        return self._send(payload)

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

        template = "red" if critical > 0 else ("orange" if high > 0 else "blue")
        fields = [
            {"label": "扫描ID", "value": scan_id},
            {"label": "目标", "value": target},
            {"label": "Critical", "value": str(critical)},
            {"label": "High", "value": str(high)},
            {"label": "Medium", "value": str(medium)},
            {"label": "Low", "value": str(low)},
            {"label": "总计", "value": str(total)},
        ]

        result = self.send_card(
            title=f"🛡️ AutoSecOps 扫描报告 — {status}",
            fields=fields,
            note=f"Scan ID: {scan_id}",
        )

        if webhook:
            self.webhook = original_webhook

        return result


def main():
    notifier = FeishuNotifier()
    notifier.send_scan_result(
        scan_id="abc12345",
        target="./my-project",
        status="completed",
        summary={"total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1},
    )


if __name__ == "__main__":
    main()
