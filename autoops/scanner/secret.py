"""
AutoSecOps — Secret Scanner
Detects exposed secrets (API keys, tokens, passwords, private keys, etc.)
in source code using regex-based pattern matching.
Inspired by: Gitleaks, TruffleHog, detect-secrets.
"""

import os
import re
import yaml
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    rule_id: str
    secret_type: str
    severity: str = "critical"
    title: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    match: str = ""          # The actual matched string (redacted in output)
    redacted_match: str = "" # e.g. "ghp_****XXXX"
    reference: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["match"] = self.redacted_match  # Never expose real secret
        return d


# ── Built-in Secret Rules ──────────────────────────────────────────────────────

BUILTIN_RULES: list[dict] = [
    # ── Cloud Providers ────────────────────────────────────────────
    {
        "id": "SEC001", "type": "AWS Access Key",
        "severity": "critical",
        "title": "AWS Access Key ID",
        "pattern": r"(?i)(aws_access_key_id|aws_secret_access_key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"](A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}['\"]",
        "message": "AWS access key detected. Rotate immediately and use IAM roles or environment variables.",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    },
    {
        "id": "SEC002", "type": "AWS Secret Key",
        "severity": "critical",
        "title": "AWS Secret Access Key",
        "pattern": r"(?i)(aws_secret|aws_access|secret_key)\s*[=:]\s*['\"][A-Za-z0-9/+=]{40,}['\"]",
        "message": "AWS secret key detected. Rotate immediately.",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    },
    {
        "id": "SEC003", "type": "GitHub Token",
        "severity": "critical",
        "title": "GitHub Personal Access Token / OAuth Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,251}|github_pat_[A-Za-z0-9_]{22,251}",
        "message": "GitHub token exposed. Revoke the token immediately in GitHub Settings → Developer settings → Personal access tokens.",
        "reference": "https://github.com/securitylab/secret-regexes",
    },
    {
        "id": "SEC004", "type": "GitHub SSH Key",
        "severity": "critical",
        "title": "GitHub SSH Private Key",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "message": "Private key detected. Remove from source code and use a secrets manager.",
        "reference": "https://docs.github.com/en/authentication/connecting-to-github-with-ssh",
    },
    {
        "id": "SEC005", "type": "Slack Token",
        "severity": "high",
        "title": "Slack Token",
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "message": "Slack token exposed. Revoke at api.slack.com/apps.",
        "reference": "https://api.slack.com/authentication/token-types",
    },
    {
        "id": "SEC006", "type": "Stripe API Key",
        "severity": "critical",
        "title": "Stripe API Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}",
        "message": "Stripe live API key detected. Rotate immediately in Stripe Dashboard.",
        "reference": "https://stripe.com/docs/keys",
    },
    {
        "id": "SEC007", "type": "Stripe Test Key",
        "severity": "medium",
        "title": "Stripe Test/Restricted Key",
        "pattern": r"sk_test_[0-9a-zA-Z]{24,}|rk_test_[0-9a-zA-Z]{24,}",
        "message": "Stripe test/restricted key detected (lower risk but should still be rotated).",
        "reference": "https://stripe.com/docs/keys",
    },
    {
        "id": "SEC008", "type": "OpenAI API Key",
        "severity": "critical",
        "title": "OpenAI / Azure OpenAI API Key",
        "pattern": r"sk-[A-Za-z0-9_]{48,}|sk-prod-[A-Za-z0-9_]{48,}",
        "message": "OpenAI API key detected. Revoke at platform.openai.com/api_keys.",
        "reference": "https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety",
    },
    {
        "id": "SEC009", "type": "Twilio API Key",
        "severity": "high",
        "title": "Twilio API Key",
        "pattern": r"SK[a-zA-Z0-9]{32}|(?i)twilio_account_sid\s*[=:]\s*AC[a-zA-Z0-9]{32}",
        "message": "Twilio credentials detected.",
        "reference": "https://www.twilio.com/docs/iam/credentials",
    },
    {
        "id": "SEC010", "type": "SendGrid API Key",
        "severity": "critical",
        "title": "SendGrid API Key",
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "message": "SendGrid API key detected. Revoke at app.sendgrid.com/settings/api_keys.",
        "reference": "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
    },
    {
        "id": "SEC011", "type": "Discord Token",
        "severity": "critical",
        "title": "Discord Bot Token",
        "pattern": r"[MN][A-Za-z\\d]{23,}\.[\\w-]{6}\.[\\w-]{27}",
        "message": "Discord bot token detected. Reset it in Discord Developer Portal.",
        "reference": "https://discord.com/developers/docs/reference",
    },
    {
        "id": "SEC012", "type": "JWT Token",
        "severity": "high",
        "title": "JWT Secret / Private Key",
        "pattern": r"(?i)(jwt_secret|JWT_SECRET|jwt\.secret|json_web_token_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "message": "JWT secret detected. Use a strong, random secret and store in a secrets manager.",
        "reference": "https://datatracker.ietf.org/doc/html/rfc7519",
    },
    {
        "id": "SEC013", "type": "Generic API Key",
        "severity": "high",
        "title": "Generic API Key",
        "pattern": r"(?i)(api_key|apikey|apiKey|API_KEY|APIKEY)\s*[=:]\s*['\"][a-zA-Z0-9_=-]{16,64}['\"]",
        "message": "Unclassified API key detected. Verify against your provider's key format.",
        "reference": "https://owasp.org/www-project-api-security/",
    },
    {
        "id": "SEC014", "type": "Password in URL",
        "severity": "high",
        "title": "Password in URL",
        "pattern": r"[a-zA-Z]+://[^:]+:[^@]+@[a-zA-Z]",
        "message": "Credentials embedded in URL. Extract and store in environment variables.",
        "reference": "https://cwe.mitre.org/data/definitions/312.html",
    },
    {
        "id": "SEC015", "type": "Database Connection String",
        "severity": "critical",
        "title": "Database Connection String with Password",
        "pattern": r"(mongodb|postgres|postgresql|mysql|redis|mssql)://[^:]+:[^@]+@",
        "message": "Database connection string with embedded password detected.",
        "reference": "https://owasp.org/www-community/attacks/LDAP_Injection",
    },
    {
        "id": "SEC016", "type": "Google OAuth",
        "severity": "critical",
        "title": "Google OAuth Access Token",
        "pattern": r"[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com",
        "message": "Google OAuth client ID detected. Ensure this is not a secret.",
        "reference": "https://developers.google.com/identity/protocols/oauth2",
    },
    {
        "id": "SEC017", "type": "SSH Private Key",
        "severity": "critical",
        "title": "SSH Private Key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----|-----BEGIN DSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----",
        "message": "SSH private key detected in source. Use a secrets manager instead.",
        "reference": "https://man.openbsd.org/ssh-keygen.1",
    },
    {
        "id": "SEC018", "type": "PyPI Token",
        "severity": "critical",
        "title": "PyPI Upload Token",
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}",
        "message": "PyPI upload token detected. Revoke at pypi.org/manage/account.",
        "reference": "https://pypi.org/security/",
    },
    {
        "id": "SEC019", "type": "NPM Token",
        "severity": "critical",
        "title": "NPM Access Token",
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "message": "NPM access token detected. Revoke at www.npmjs.com/settings/tokens.",
        "reference": "https://docs.npmjs.com/about-access-tokens",
    },
    {
        "id": "SEC020", "type": "Mailgun API Key",
        "severity": "high",
        "title": "Mailgun API Key",
        "pattern": r"(?i)mailgun-[a-zA-Z0-9]{32}",
        "message": "Mailgun API key detected.",
        "reference": "https://documentation.mailgun.com/en/latest/faqs.html#api-keys",
    },
    {
        "id": "SEC021", "type": "S3 Bucket with Credentials",
        "severity": "critical",
        "title": "AWS S3 Credentials",
        "pattern": r"[A-Za-z0-9/+=]{40,}.*s3\.amazonaws\.com|s3://[a-zA-Z0-9-]+:[A-Za-z0-9/+=]{40,}@",
        "message": "AWS S3 credentials detected. Rotate immediately.",
        "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingAWSSDK.html",
    },
    {
        "id": "SEC022", "type": "Generic Secret",
        "severity": "medium",
        "title": "Generic Secret String",
        "pattern": r"(?i)(secret|password|passwd|pwd|token|auth)[_\"\'\s]*[=:][_\"\'\s]*['\"][^'\"]{6,64}['\"]",
        "message": "Generic secret string detected. Verify if this is a genuine secret.",
        "reference": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Secret Scanner ────────────────────────────────────────────────────────────

class SecretScanner:
    """
    Scan source code files for leaked secrets.
    Loads rules from YAML and uses built-in regex patterns.
    Files are scanned in parallel for performance.
    """

    # File extensions / names to always skip
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
        ".bin", ".exe", ".dll", ".so", ".dylib",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".db", ".sqlite", ".sqlite3",
        ".log", ".lock", ".sum",  # lock files, go.sum
    }

    SKIP_FILES = {
        ".git", ".svn", ".hg",
        "node_modules", ".venv", "venv", "__pycache__",
        ".pytest_cache", ".mypy_cache",
        "package-lock.json",  # Only skip if also containing secrets is rare
    }

    def __init__(
        self,
        detectors: list[str] | None = None,   # Filter by rule IDs
        rules_dir: str | Path = "configs/rules",
        exclude_paths: list[str] | None = None,
        redact: bool = True,
    ):
        self.detectors = set(detectors) if detectors else set()
        self.rules_dir = Path(rules_dir)
        self.exclude_paths = exclude_paths or []
        self.redact = redact
        self._rules: list[dict] = []
        self._load_rules()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, target_path: str | Path) -> dict:
        """
        Scan a directory or file for secrets.
        Returns dict with counts and list of findings.
        """
        target = Path(target_path)
        findings: list[SecretFinding] = []
        files_scanned = 0

        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        for file_path in self._iter_files(target):
            results = self._scan_file(file_path)
            findings.extend(results)
            files_scanned += 1

        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), f.file, f.line))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "total": len(findings),
            "files_scanned": files_scanned,
            **counts,
            "findings": [f.to_dict() for f in findings],
        }

    # ── Rule Loading ──────────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        """Load built-in rules + YAML override rules."""
        self._rules = []
        for rule in BUILTIN_RULES:
            if not self.detectors or rule["id"] in self.detectors:
                compiled = {**rule, "_compiled": re.compile(rule["pattern"])}
                self._rules.append(compiled)

        # Load YAML rules
        if self.rules_dir.exists():
            extra_path = self.rules_dir / "secrets.yaml"
            if extra_path.exists():
                try:
                    with open(extra_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    for rule in data.get("rules", []):
                        if not self.detectors or rule.get("id") in self.detectors:
                            compiled = {**rule, "_compiled": re.compile(rule["pattern"])}
                            self._rules.append(compiled)
                except Exception as e:
                    print(f"[secret] warn: failed to load {extra_path}: {e}")

    # ── File Iteration ────────────────────────────────────────────────────────

    def _iter_files(self, root: Path):
        if root.is_file():
            if not self._should_skip(root):
                yield root
            return
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip directories
            dirnames[:] = [d for d in dirnames if not self._should_skip_dir(d)]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if not self._should_skip(fpath):
                    yield fpath

    def _should_skip(self, path: Path) -> bool:
        p = str(path)
        if path.suffix.lower() in self.SKIP_EXTENSIONS:
            return True
        for skip in self.SKIP_FILES:
            if skip in p:
                return True
        for pattern in self.exclude_paths:
            if pattern in p or path.match(pattern):
                return True
        return False

    def _should_skip_dir(self, d: str) -> bool:
        skip_dirs = {".git", ".svn", "node_modules", ".venv", "venv", "__pycache__",
                     ".pytest_cache", ".mypy_cache", "vendor", "dist", "build"}
        return d in skip_dirs

    # ── Core Scanning ────────────────────────────────────────────────────────

    def _scan_file(self, path: Path) -> list[SecretFinding]:
        findings = []
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return findings

        for line_no, line in enumerate(lines, 1):
            for rule in self._rules:
                compiled = rule.get("_compiled")
                if compiled is None:
                    continue
                for match in compiled.finditer(line):
                    secret_str = match.group(0)
                    findings.append(SecretFinding(
                        rule_id=rule["id"],
                        secret_type=rule.get("type", rule["id"]),
                        severity=rule.get("severity", "high"),
                        title=rule.get("title", rule["id"]),
                        message=rule.get("message", ""),
                        file=str(path),
                        line=line_no,
                        match=secret_str,
                        redacted_match=self._redact(secret_str, rule["id"]),
                        reference=rule.get("reference", ""),
                    ))

        return findings

    def _redact(self, secret: str, rule_id: str) -> str:
        """Replace secret with a partially redacted version for safe output."""
        if not self.redact or len(secret) <= 8:
            return "***REDACTED***"
        if rule_id == "SEC003":  # GitHub token
            return secret[:3] + "*" * (len(secret) - 6) + secret[-3:]
        elif len(secret) <= 12:
            return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
        else:
            return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse, json, sys

    parser = argparse.ArgumentParser(description="AutoSecOps Secret Scanner")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--exclude", action="append", default=[],
                        help="Paths to exclude")
    parser.add_argument("--json", dest="output_json", action="store_true")
    args = parser.parse_args()

    scanner = SecretScanner(exclude_paths=args.exclude)
    try:
        result = scanner.scan(args.target)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'='*60}")
        print(f"  Secret Scan Results — {args.target}")
        print(f"{'='*60}")
        print(f"  Files scanned  : {result['files_scanned']}")
        print(f"  Total secrets  : {result['total']}")
        print(f"  Critical       : {result['critical']}")
        print(f"  High           : {result['high']}")
        print(f"  Medium         : {result['medium']}")
        print(f"  Low            : {result['low']}")
        print(f"{'='*60}\n")

        for f in result["findings"]:
            print(f"  [{f['severity'].upper()}] {f['rule_id']} — {f['title']}")
            print(f"    File: {f['file']}:{f['line']}")
            print(f"    Type: {f['secret_type']}")
            print(f"    Match: {f['match']}")
            print(f"    {f['message'][:200]}")
            print()


if __name__ == "__main__":
    main()
