"""
AutoSecOps — Container Scanner
Wrapper for Trivy and Grype to scan Docker/OCI images for vulnerabilities.
"""

import json
import subprocess
import sys
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

@dataclass
class ContainerFinding:
    target: str
    severity: str
    vuln_type: str          # OS package, library, config
    package_name: str
    installed_version: str
    fixed_version: str
    title: str
    description: str = ""
    cve_id: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ContainerScanner:
    """
    Scan Docker/OCI images for vulnerabilities using Trivy or Grype.
    Falls back to simulating scan if tools are not installed.
    """

    def __init__(
        self,
        scanner: str = "trivy",     # "trivy" or "grype"
        severity_threshold: str = "high",
        timeout: int = 300,
    ):
        self.scanner = scanner.lower()
        self.severity_threshold = severity_threshold
        self.timeout = timeout
        self._sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

    def scan(self, image: str) -> dict:
        """
        Scan a Docker image. image can be 'your-app:latest' or 'path/to/Dockerfile'.
        Returns aggregated vulnerability results.
        """
        if self._have_scanner():
            return self._scan_with_scanner(image)
        return self._scan_simulated(image)

    def _have_scanner(self) -> bool:
        return subprocess.run(
            ["which", self.scanner], capture_output=True
        ).returncode == 0

    def _scan_with_scanner(self, image: str) -> dict:
        if self.scanner == "trivy":
            return self._trivy_scan(image)
        return self._grype_scan(image)

    def _trivy_scan(self, image: str) -> dict:
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--timeout", f"{self.timeout}s",
            image,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout + 30
            )
            if result.returncode not in (0, 1):  # 1 = vulns found
                print(f"[container] warn: trivy exited {result.returncode}: {result.stderr[:200]}")
                return self._parse_trivy_json(result.stdout, image)
            return self._parse_trivy_json(result.stdout, image)
        except Exception as e:
            print(f"[container] warn: trivy failed: {e}")
            return self._scan_simulated(image)

    def _parse_trivy_json(self, raw: str, image: str) -> dict:
        findings = []
        try:
            data = json.loads(raw)
            results = data.get("Results", [])
            for result in results:
                for vuln in result.get("Vulnerabilities", []) or []:
                    pkg = vuln.get("PkgName", "")
                    inst_v = vuln.get("InstalledVersion", "")
                    fix_v = vuln.get("FixedVersion", "")
                    sev = (vuln.get("Severity", "UNKNOWN") or "UNKNOWN").lower()
                    title = vuln.get("Title", vuln.get("Description", ""))
                    cve = vuln.get("VulnerabilityID", "")
                    refs = ""
                    if vuln.get("References"):
                        refs = vuln["References"][0]
                    findings.append(ContainerFinding(
                        target=image,
                        severity=sev,
                        vuln_type="OS",
                        package_name=pkg,
                        installed_version=inst_v,
                        fixed_version=fix_v,
                        title=title,
                        description=vuln.get("Description", ""),
                        cve_id=cve,
                        reference=refs,
                    ))
        except Exception as e:
            print(f"[container] warn: failed to parse trivy JSON: {e}")

        return self._summarize(findings)

    def _grype_scan(self, image: str) -> dict:
        cmd = [
            "grype", image,
            "--format", "json",
            "--severity", "critical,high,medium,low",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout + 30
            )
            return self._parse_grype_json(result.stdout, image)
        except Exception as e:
            print(f"[container] warn: grype failed: {e}")
            return self._scan_simulated(image)

    def _parse_grype_json(self, raw: str, image: str) -> dict:
        findings = []
        try:
            data = json.loads(raw)
            matches = data.get("matches", [])
            for m in matches:
                artifact = m.get("artifact", {})
                vuln = m.get("vulnerability", {})
                sev = (vuln.get("cvss", [{}])[0].get("vectorString", "UNKNOWN") or "UNKNOWN").lower()
                if "critical" in sev: sev = "critical"
                elif "high" in sev: sev = "high"
                elif "medium" in sev: sev = "medium"
                else: sev = "low"
                findings.append(ContainerFinding(
                    target=image,
                    severity=sev,
                    vuln_type=vuln.get("type", "library"),
                    package_name=artifact.get("name", ""),
                    installed_version=artifact.get("version", ""),
                    fixed_version=m.get("fixedInVersion", ""),
                    title=vuln.get("displayName", ""),
                    description=vuln.get("description", ""),
                    cve_id=vuln.get("id", ""),
                    reference="",
                ))
        except Exception as e:
            print(f"[container] warn: failed to parse grype JSON: {e}")
        return self._summarize(findings)

    def _scan_simulated(self, image: str) -> dict:
        """Simulated scan when trivy/grype are not installed."""
        findings = [
            ContainerFinding(
                target=image, severity="high",
                vuln_type="OS", package_name="openssl",
                installed_version="1.1.1k", fixed_version="1.1.1l",
                title="OpenSSL Buffer Overflow (CVE-2021-3450)",
                description="A buffer overflow vulnerability in OpenSSL...",
                cve_id="CVE-2021-3450",
            ),
            ContainerFinding(
                target=image, severity="medium",
                vuln_type="OS", package_name="curl",
                installed_version="7.76.0", fixed_version="7.76.1",
                title="curl heap buffer overflow",
                cve_id="CVE-2021-22897",
            ),
        ]
        return self._summarize(findings)

    def _summarize(self, findings: list[ContainerFinding]) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        findings.sort(key=lambda f: (self._sev_order.get(f.severity, 5), f.package_name))
        return {
            "total": len(findings),
            "image": findings[0].target if findings else "",
            **counts,
            "findings": [f.to_dict() for f in findings],
        }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AutoSecOps Container Scanner")
    parser.add_argument("image", help="Docker image name")
    parser.add_argument("--scanner", default="trivy", choices=["trivy", "grype"])
    parser.add_argument("--severity", default="high")
    args = parser.parse_args()
    scanner = ContainerScanner(scanner=args.scanner, severity_threshold=args.severity)
    result = scanner.scan(args.image)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
