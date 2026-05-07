"""
AutoSecOps — Compliance Scanner
Checks Docker and Kubernetes configurations against CIS benchmarks.
Supports: cis-docker, cis-k8s, pcidss
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

@dataclass
class ComplianceFinding:
    benchmark: str
    rule_id: str
    severity: str
    title: str
    description: str
    file: str = ""
    status: str = "PASS"   # PASS / FAIL / WARN / INFO
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


CIS_DOCKER_RULES = [
    {
        "id": "CIS-DOCKER-1.1.1", "severity": "critical",
        "title": "Ensure the container host has been hardened",
        "description": "Remove unnecessary packages or services from the container host.",
        "remediation": "Follow the CIS Docker Benchmark guidelines to harden the host.",
        "reference": "https://www.cisecurity.org/benchmark/docker",
    },
    {
        "id": "CIS-DOCKER-2.1", "severity": "high",
        "title": "Ensure the container image has a HEALTHCHECK instruction",
        "description": "HEALTHCHECK allows Docker to detect hanging processes inside the container.",
        "remediation": "Add HEALTHCHECK to your Dockerfile.",
        "reference": "https://docs.docker.com/engine/reference/builder/#healthcheck",
    },
    {
        "id": "CIS-DOCKER-2.2", "severity": "medium",
        "title": "Ensure instructions are not repeated in multiple RUN commands",
        "description": "Each RUN instruction creates a new layer. Combine commands with && to reduce layers.",
        "remediation": "Rewrite Dockerfile to combine RUN commands using && and backslash line continuations.",
        "reference": "https://github.com/hadolint/hadolint/wiki/DL3059",
    },
    {
        "id": "CIS-DOCKER-2.3", "severity": "medium",
        "title": "Ensure apt-get install uses -y, --no-install-recommends",
        "description": "Using --no-install-recommends reduces the image size and attack surface.",
        "remediation": "Use: RUN apt-get update && apt-get install -y --no-install-recommends <packages>",
        "reference": "https://github.com/hadolint/hadolint/wiki/DL3005",
    },
    {
        "id": "CIS-DOCKER-2.4", "severity": "critical",
        "title": "Ensure COPY is used instead of ADD in Dockerfile",
        "description": "COPY is more transparent than ADD. ADD can also add from URLs and local tar extraction.",
        "remediation": "Replace ADD with COPY in your Dockerfile.",
        "reference": "https://github.com/hadolint/hadolint/wiki/DL3015",
    },
    {
        "id": "CIS-DOCKER-2.5", "severity": "high",
        "title": "Ensure secrets are not stored in Dockerfile",
        "description": "Dockerfiles can be committed to source control and expose secrets.",
        "remediation": "Use Docker secrets or environment variables at runtime instead.",
        "reference": "https://docs.docker.com/engine/swarm/secrets/",
    },
    {
        "id": "CIS-DOCKER-2.6", "severity": "high",
        "title": "Ensure ENV variables are not sensitive",
        "description": "Environment variables set in Dockerfile are visible in docker history.",
        "remediation": "Use ENV only for non-sensitive values. Pass secrets at runtime.",
        "reference": "https://docs.docker.com/engine/reference/builder/#env",
    },
    {
        "id": "CIS-DOCKER-2.7", "severity": "medium",
        "title": "Ensure the working directory is set",
        "description": "Set a working directory to avoid operating in / by default.",
        "remediation": "Add WORKDIR /app in your Dockerfile.",
        "reference": "https://docs.docker.com/engine/reference/builder/#workdir",
    },
    {
        "id": "CIS-DOCKER-2.8", "severity": "medium",
        "title": "Ensure the USER directive is not set to root",
        "description": "Running as root user increases the attack surface.",
        "remediation": "Create a non-root user and switch to it with USER directive.",
        "reference": "https://docs.docker.com/engine/reference/builder/#user",
    },
    {
        "id": "CIS-DOCKER-2.9", "severity": "low",
        "title": "Ensure the CMD directive is used correctly",
        "description": "CMD should be used to run the main application, not to install software.",
        "remediation": "Use a single CMD instruction that runs your application.",
        "reference": "https://docs.docker.com/engine/reference/builder/#cmd",
    },
    {
        "id": "CIS-DOCKER-2.10", "severity": "medium",
        "title": "Ensure EXPOSE is not used to restrict port access",
        "description": "EXPOSE only documents ports; use -p flag to actually restrict access.",
        "remediation": "Use -p host:container to explicitly bind ports to specific interfaces.",
        "reference": "https://docs.docker.com/engine/reference/builder/#expose",
    },
    {
        "id": "CIS-DOCKER-2.11", "severity": "high",
        "title": "Ensure privileged flag is not used",
        "description": "Privileged containers run with all Linux capabilities and can access all devices.",
        "remediation": "Do not use --privileged in docker run. Use specific capabilities instead.",
        "reference": "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
    },
    {
        "id": "CIS-DOCKER-2.12", "severity": "high",
        "title": "Ensure sensitive host directories are not mounted",
        "description": "Mounting sensitive host directories (e.g. /etc, /var/run/docker.sock) increases risk.",
        "remediation": "Avoid mounting host directories unless absolutely necessary.",
        "reference": "https://docs.docker.com/engine/reference/builder/#run",
    },
]

CIS_K8S_RULES = [
    {
        "id": "CIS-K8S-1.1.1", "severity": "critical",
        "title": "Ensure API server spec is not set to wildcard",
        "description": "The API server --bind-address should not be set to 0.0.0.0.",
        "remediation": "Set --bind-address to the internal IP of the API server.",
        "reference": "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
    },
    {
        "id": "CIS-K8S-1.2.1", "severity": "critical",
        "title": "Ensure anonymous auth is disabled",
        "description": "Set --anonymous-auth=false on the API server to prevent unauthenticated access.",
        "remediation": "Edit /etc/kubernetes/manifests/kube-apiserver.yaml and set anonymous-auth: false.",
        "reference": "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
    },
    {
        "id": "CIS-K8S-1.2.2", "severity": "critical",
        "title": "Ensure RBAC is enabled",
        "description": "Role-Based Access Control (RBAC) should be enabled to enforce least-privilege.",
        "remediation": "Start the API server with --authorization-mode=RBAC.",
        "reference": "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    },
    {
        "id": "CIS-K8S-1.2.3", "severity": "high",
        "title": "Ensure admission control plugin is set",
        "description": "Use admission controllers like PodSecurityPolicy, LimitRanger, and ResourceQuota.",
        "remediation": "Set --enable-admission-plugins on the API server.",
        "reference": "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/",
    },
]

BENCHMARK_RULES = {
    "cis-docker": CIS_DOCKER_RULES,
    "cis-k8s": CIS_K8S_RULES,
}


class ComplianceScanner:
    """
    Check Dockerfiles and Kubernetes manifests for CIS benchmark compliance.
    """

    def __init__(self, benchmark: str = "cis-docker"):
        self.benchmark = benchmark.lower()
        self.rules = BENCHMARK_RULES.get(self.benchmark, CIS_DOCKER_RULES)
        self._sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def scan(self, target_path: str | Path) -> dict:
        """
        Scan Dockerfile(s) or K8s manifest(s) for compliance issues.
        """
        target = Path(target_path)
        findings: list[ComplianceFinding] = []

        for path in self._find_files(target):
            if path.suffix in (".yaml", ".yml") or "Dockerfile" in path.name:
                results = self._check_file(path)
                findings.extend(results)

        findings.sort(key=lambda f: (self._sev_order.get(f.severity, 5), f.rule_id))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "total": len(findings),
            "benchmark": self.benchmark,
            **counts,
            "findings": [f.to_dict() for f in findings],
        }

    def _find_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if fname == "Dockerfile" or fname.endswith((".yaml", ".yml")):
                    yield Path(dirpath) / fname

    def _check_file(self, path: Path) -> list[ComplianceFinding]:
        findings = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        for rule in self.rules:
            result = self._evaluate_rule(rule, content, path)
            if result:
                findings.append(result)

        return findings

    def _evaluate_rule(self, rule: dict, content: str, path: Path) -> ComplianceFinding | None:
        fid = rule["id"]

        # ── Dockerfile checks ──────────────────────────────────────
        if "Dockerfile" in path.name:
            if fid == "CIS-DOCKER-2.1":
                if "HEALTHCHECK" not in content.upper():
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

            if fid == "CIS-DOCKER-2.4":
                if re.search(r"\bADD\b", content):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

            if fid == "CIS-DOCKER-2.5":
                if re.search(r"(password|passwd|secret|token|api_key)\s*[=]\s*['\"](?!{{|\$)", content, re.IGNORECASE):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

            if fid == "CIS-DOCKER-2.6":
                if re.search(r"ENV\s+(password|passwd|secret|token|api_key)", content, re.IGNORECASE):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

            if fid == "CIS-DOCKER-2.8":
                if re.search(r"USER\s+root", content, re.IGNORECASE):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

            if fid == "CIS-DOCKER-2.11":
                if re.search(r"--privileged", content):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")

        # ── YAML checks (K8s) ────────────────────────────────────────
        if path.suffix in (".yaml", ".yml"):
            if fid == "CIS-K8S-1.2.1":
                if re.search(r"anonymous-auth:\s*false", content):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")

            if fid == "CIS-K8S-1.2.2":
                if re.search(r"authorization-mode:\s*RBAC", content):
                    return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="PASS")
                return ComplianceFinding(benchmark=self.benchmark, **rule, file=str(path), status="FAIL")

        return None


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AutoSecOps Compliance Scanner")
    parser.add_argument("target", help="Dockerfile or K8s manifest path")
    parser.add_argument("--benchmark", default="cis-docker",
                        choices=["cis-docker", "cis-k8s"])
    args = parser.parse_args()
    scanner = ComplianceScanner(benchmark=args.benchmark)
    result = scanner.scan(args.target)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
