"""
AutoSecOps — SAST Scanner
Static Application Security Testing using regex-based rule matching.
Supports: Python, Go, JavaScript, Java, Node.js
"""

import re
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: str          # critical / high / medium / low / info
    title: str
    message: str
    file: str
    line: int
    col: int = 0
    code_snippet: str = ""
    reference: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

# ── Language Extensions ───────────────────────────────────────────────────────

EXT_MAP = {
    "python":  [".py"],
    "go":      [".go"],
    "javascript": [".js", ".jsx", ".mjs"],
    "java":    [".java"],
    "nodejs":  [".js", ".jsx", ".ts", ".tsx", ".mjs"],
}

DEFAULT_LANGS = ["python", "go", "javascript", "java", "nodejs"]

# ── Built-in Rules ─────────────────────────────────────────────────────────────

BUILTIN_RULES: dict[str, list[dict]] = {
    "python": [
        {
            "id": "PY001", "severity": "critical", "cwe": "CWE-89",
            "title": "SQL Injection",
            "pattern": r"(execute|cursor\.execute|executemany)\s*\(\s*f?['\"](SELECT|INSERT|UPDATE|DELETE).*?\%s",
            "message": "Possible SQL injection. Use parameterized queries instead of string formatting.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        },
        {
            "id": "PY002", "severity": "critical", "cwe": "CWE-78",
            "title": "Command Injection",
            "pattern": r"(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*(f?['\"]|os\.environ)",
            "message": "Possible command injection. Avoid shell=True or string interpolation in subprocess calls.",
            "reference": "https://owasp.org/www-community/attacks/Command_Injection",
        },
        {
            "id": "PY003", "severity": "high", "cwe": "CWE-502",
            "title": "Unsafe Deserialization",
            "pattern": r"(pickle\.loads|pickle\.load|marshal\.loads|yaml\.unsafe_load|yaml\.load\s*\([^)]*Loader\s*=\s*None)",
            "message": "Unsafe deserialization can lead to remote code execution. Use safe_load or specify a safe Loader.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Deserialization",
        },
        {
            "id": "PY004", "severity": "high", "cwe": "CWE-798",
            "title": "Hardcoded Credentials",
            "pattern": r"['\"](password|passwd|pwd|api_key|apikey|secret|token)\s*['\"]\s*[=:]\s*['\"][^'\"]{4,}",
            "message": "Hardcoded credential detected. Use environment variables or a secrets manager.",
            "reference": "https://owasp.org/www-series/OWASP-API-Security-Top-10-2019-released/",
        },
        {
            "id": "PY005", "severity": "medium", "cwe": "CWE-338",
            "title": "Weak Random Number",
            "pattern": r"random\.(random|randint|choice)\s*\(\s*\)",
            "message": "Use secrets.randbelow() or os.urandom() for security-sensitive randomness.",
            "reference": "https://cwe.mitre.org/data/definitions/338.html",
        },
        {
            "id": "PY006", "severity": "high", "cwe": "CWE-22",
            "title": "Path Traversal",
            "pattern": r"(open|Path)\s*\([^)]*\%s|os\.path\.join\s*\([^)]*request\.(args|form|values)",
            "message": "Possible path traversal. Validate and sanitize user input before using in file paths.",
            "reference": "https://owasp.org/www-community/attacks/Path_Traversal",
        },
        {
            "id": "PY007", "severity": "high", "cwe": "CWE- write_file-Without-Read",
            "title": "Debug Mode Enabled",
            "pattern": r"DEBUG\s*=\s*True",
            "message": "Debug mode is enabled in production code. This can leak sensitive information.",
            "reference": "https://owasp.org/",
        },
        {
            "id": "PY008", "severity": "medium", "cwe": "CWE-200",
            "title": "Information Exposure",
            "pattern": r"print\s*\(\s*(request\.|os\.environ|secrets\.)",
            "message": "Possible sensitive information exposure through print().",
            "reference": "https://cwe.mitre.org/data/definitions/200.html",
        },
    ],
    "go": [
        {
            "id": "GO001", "severity": "critical", "cwe": "CWE-78",
            "title": "Command Injection",
            "pattern": r"exec\.Command\s*\(\s*\"(sh|bash|cmd)\"\s*,\s*args\)|os/exec\.Command\s*\([^)]*\+",
            "message": "Possible command injection when using exec.Command with string concatenation.",
            "reference": "https://owasp.org/www-community/attacks/Command_Injection",
        },
        {
            "id": "GO002", "severity": "high", "cwe": "CWE-295",
            "title": "Insecure TLS Config",
            "pattern": r"(InsecureSkipVerify\s*:\s*true|TLSClientConfig\s*:\s*&tls\.Config\{\s*InsecureSkipVerify\s*:\s*true})",
            "message": "InsecureSkipVerify is set to true. This disables TLS certificate verification.",
            "reference": "https://cwe.mitre.org/data/definitions/295.html",
        },
        {
            "id": "GO003", "severity": "high", "cwe": "CWE-798",
            "title": "Hardcoded Credentials",
            "pattern": r"(password|passwd|secret|token|api_key)\s*[:=]\s*\"[^\"]{4,}\"",
            "message": "Hardcoded credential detected. Use environment variables.",
            "reference": "https://owasp.org/www-series/OWASP-API-Security-Top-10-2019-released/",
        },
        {
            "id": "GO004", "severity": "medium", "cwe": "CWE-190",
            "title": "Integer Overflow",
            "pattern": r"int\(.*?\)\s*[\+\-\*]\s*int\(?.*?\)?",
            "message": "Potential integer overflow. Validate integer inputs.",
            "reference": "https://cwe.mitre.org/data/definitions/190.html",
        },
        {
            "id": "GO005", "severity": "high", "cwe": "CWE-22",
            "title": "Path Traversal",
            "pattern": r"(ioutil\.)?(ReadFile|ReadDir|WriteFile)\s*\([^)]*\+",
            "message": "Possible path traversal when concatenating user input into file paths.",
            "reference": "https://owasp.org/www-community/attacks/Path_Traversal",
        },
        {
            "id": "GO006", "severity": "medium", "cwe": "CWE-312",
            "title": "Cleartext Transmission",
            "pattern": r"http\.(Get|Post|Do)\s*\(\s*\"http://",
            "message": "Cleartext HTTP request detected. Use HTTPS instead.",
            "reference": "https://cwe.mitre.org/data/definitions/312.html",
        },
    ],
    "javascript": [
        {
            "id": "JS001", "severity": "critical", "cwe": "CWE-79",
            "title": "Cross-Site Scripting (XSS)",
            "pattern": r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML)\s*\(",
            "message": "Possible XSS. Avoid document.write() or innerHTML with user input. Use textContent or sanitizers.",
            "reference": "https://owasp.org/www-community/attacks/xss/",
        },
        {
            "id": "JS002", "severity": "critical", "cwe": "CWE-89",
            "title": "SQL Injection",
            "pattern": r"(query|execute|find)\s*\(\s*['\"]SELECT|connection\.(query|execute)\s*\(",
            "message": "Possible SQL injection. Use parameterized queries.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        },
        {
            "id": "JS003", "severity": "high", "cwe": "CWE-798",
            "title": "Hardcoded Credentials",
            "pattern": r"(password|passwd|secret|token|apiKey|api_key)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            "message": "Hardcoded credential detected. Use environment variables.",
            "reference": "https://owasp.org/www-series/OWASP-API-Security-Top-10-2019-released/",
        },
        {
            "id": "JS004", "severity": "high", "cwe": "CWE-94",
            "title": "Code Injection",
            "pattern": r"(eval|Function|setTimeout|setInterval)\s*\(\s*(req\.|process\.|user|input)",
            "message": "Possible code injection via eval() or similar. Avoid dynamic code execution.",
            "reference": "https://owasp.org/www-community/attacks/Code_Injection",
        },
        {
            "id": "JS005", "severity": "medium", "cwe": "CWE-200",
            "title": "Sensitive Data Exposure",
            "pattern": r"console\.(log|warn|error)\s*\(\s*(process\.env|secrets\.|token)",
            "message": "Possible sensitive data exposure through console.",
            "reference": "https://cwe.mitre.org/data/definitions/200.html",
        },
        {
            "id": "JS006", "severity": "high", "cwe": "CWE-754",
            "title": "Missing SSL Verify",
            "pattern": r"rejectUnauthorized\s*:\s*false",
            "message": "SSL certificate verification is disabled.",
            "reference": "https://cwe.mitre.org/data/definitions/754.html",
        },
    ],
    "java": [
        {
            "id": "JAVA001", "severity": "critical", "cwe": "CWE-78",
            "title": "Command Injection",
            "pattern": r"(Runtime\.getRuntime\(\)\.exec|RProcessBuilder)\s*\(",
            "message": "Possible command injection. Avoid Runtime.exec() with string concatenation.",
            "reference": "https://owasp.org/www-community/attacks/Command_Injection",
        },
        {
            "id": "JAVA002", "severity": "high", "cwe": "CWE-501",
            "title": "Trust Boundary Violation",
            "pattern": r"(request\.getParameter|request\.getHeader)\s*\(\s*['\"]",
            "message": "User input flows into session without proper validation.",
            "reference": "https://cwe.mitre.org/data/definitions/501.html",
        },
        {
            "id": "JAVA003", "severity": "high", "cwe": "CWE-798",
            "title": "Hardcoded Password",
            "pattern": r"(password|passwd|secret)\s*=\s*\"[^\"]{4,}\"",
            "message": "Hardcoded password detected. Use environment variables.",
            "reference": "https://owasp.org/www-series/OWASP-API-Security-Top-10-2019-released/",
        },
        {
            "id": "JAVA004", "severity": "medium", "cwe": "CWE-312",
            "title": "Cleartext Log",
            "pattern": r"log\.(info|warn|error|debug)\s*\(\s*(password|token|secret|key)",
            "message": "Sensitive data logged in cleartext.",
            "reference": "https://cwe.mitre.org/data/definitions/312.html",
        },
    ],
    "nodejs": [
        {
            "id": "NODE001", "severity": "critical", "cwe": "CWE-89",
            "title": "SQL Injection",
            "pattern": r"(db\.)?(query|execute)\s*\(\s*['\"]SELECT|pool\.query\s*\(",
            "message": "Possible SQL injection. Use parameterized queries.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        },
        {
            "id": "NODE002", "severity": "critical", "cwe": "CWE-94",
            "title": "Code Injection",
            "pattern": r"(eval|vm\.runInCode)\s*\(\s*req\.",
            "message": "Possible code injection via eval().",
            "reference": "https://owasp.org/www-community/attacks/Code_Injection",
        },
        {
            "id": "NODE003", "severity": "high", "cwe": "CWE-754",
            "title": "Missing JWT Verify",
            "pattern": r"jwt\.sign\(|jwt\.verify\(",
            "message": "JWT used without proper verification of signature.",
            "reference": "https://cwe.mitre.org/data/definitions/754.html",
        },
    ],
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── SAST Scanner ──────────────────────────────────────────────────────────────

class SASTScanner:
    """
    Regex-based SAST scanner.
    Loads rules from YAML files under configs/rules/ or uses built-in rules.
    Scans files in parallel using ThreadPoolExecutor.
    """

    def __init__(
        self,
        languages: list[str] | None = None,
        rules_dir: str | Path = "configs/rules",
        severity_threshold: str = "info",
        exclude_paths: list[str] | None = None,
    ):
        self.languages = languages or DEFAULT_LANGS
        self.rules_dir = Path(rules_dir)
        self.severity_threshold = severity_threshold
        self.exclude_paths = exclude_paths or []
        self._rules: dict[str, list[dict]] = {}
        self._load_rules()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, target_path: str | Path) -> dict:
        """
        Scan a directory or file.
        Returns dict with keys: total, critical, high, medium, low, info, findings
        """
        target = Path(target_path)
        findings: list[Finding] = []
        files_scanned = 0

        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        for file_path in self._iter_files(target):
            if self._is_excluded(file_path):
                continue
            lang = self._detect_lang(file_path)
            if lang and lang in self._rules:
                results = self._scan_file(file_path, lang)
                findings.extend(results)
                files_scanned += 1

        # Sort findings by severity then line number
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), f.line))

        return self._summarize(findings, files_scanned)

    # ── Rule Loading ──────────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        """Load rules from built-in dict + YAML rule files."""
        self._rules = {lang: list(rules) for lang, rules in BUILTIN_RULES.items()}

        if self.rules_dir.exists():
            for yaml_file in self.rules_dir.glob("*.yaml"):
                lang = yaml_file.stem
                if lang in EXT_MAP:
                    try:
                        with open(yaml_file, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f) or {}
                        extra = data.get("rules", [])
                        if lang in self._rules:
                            existing = {r["id"] for r in self._rules[lang]}
                            self._rules[lang].extend(r for r in extra if r.get("id") not in existing)
                        else:
                            self._rules[lang] = extra
                    except Exception as e:
                        print(f"[sast] warn: failed to load {yaml_file}: {e}")

        # Compile regex patterns
        for lang, rules in self._rules.items():
            compiled = []
            for rule in rules:
                try:
                    compiled.append({**rule, "_compiled": re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)})
                except re.error as e:
                    print(f"[sast] warn: bad regex in rule {rule.get('id','?')}: {e}")
                    compiled.append({**rule, "_compiled": None})
            self._rules[lang] = compiled

    # ── File Iteration ────────────────────────────────────────────────────────

    def _iter_files(self, root: Path):
        """Yield Path objects for all source files under root."""
        if root.is_file():
            yield root
            return

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune common non-source directories
            dirnames[:] = [d for d in dirnames if not self._is_excluded(Path(dirpath) / d)]

            for fname in filenames:
                yield Path(dirpath) / fname

    def _is_excluded(self, path: Path) -> bool:
        """Check if a path matches any exclude pattern."""
        path_str = str(path)
        for pattern in self.exclude_paths:
            pattern = pattern.strip().rstrip("/")
            if pattern.startswith("**/"):
                pattern = pattern[3:]
            if pattern in path_str or path.match(pattern):
                return True
        return False

    def _detect_lang(self, path: Path) -> str | None:
        """Detect language from file extension."""
        ext = path.suffix.lower()
        for lang, exts in EXT_MAP.items():
            if ext in exts:
                return lang
        return None

    # ── Core Scanning ────────────────────────────────────────────────────────

    def _scan_file(self, path: Path, lang: str) -> list[Finding]:
        """Scan a single file for all rules of the given language."""
        findings = []
        threshold_idx = SEVERITY_ORDER.get(self.severity_threshold, 4)

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        lines = content.splitlines()

        for rule in self._rules.get(lang, []):
            compiled = rule.get("_compiled")
            if compiled is None:
                continue

            # Check severity threshold
            sev_idx = SEVERITY_ORDER.get(rule["severity"], 5)
            if sev_idx > threshold_idx:
                continue

            for match in compiled.finditer(content):
                start = match.start()
                line_num = content[: start + 1].count("\n")
                col_num = start - content[:start].rfind("\n")

                snippet = ""
                if 0 <= line_num < len(lines):
                    snippet = lines[line_num].strip()

                findings.append(Finding(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    title=rule["title"],
                    message=rule["message"],
                    file=str(path),
                    line=line_num + 1,
                    col=col_num,
                    code_snippet=snippet,
                    reference=rule.get("reference", ""),
                    cwe=rule.get("cwe", ""),
                ))

        return findings

    # ── Result Aggregation ────────────────────────────────────────────────────

    def _summarize(self, findings: list[Finding], files_scanned: int) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "total": len(findings),
            "files_scanned": files_scanned,
            **counts,
            "findings": [f.to_dict() for f in findings],
        }


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    import argparse, json, sys

    parser = argparse.ArgumentParser(description="AutoSecOps SAST Scanner")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--lang", "--language", dest="languages", action="append",
                        help="Languages to scan (python, go, javascript, java, nodejs)")
    parser.add_argument("--severity", default="info",
                        choices=["critical", "high", "medium", "low", "info"])
    parser.add_argument("--exclude", action="append", default=[],
                        help="Paths or patterns to exclude")
    parser.add_argument("--rules-dir", default="configs/rules")
    parser.add_argument("--json", dest="output_json", action="store_true")
    args = parser.parse_args()

    scanner = SASTScanner(
        languages=args.languages,
        rules_dir=args.rules_dir,
        severity_threshold=args.severity,
        exclude_paths=args.exclude,
    )

    try:
        result = scanner.scan(args.target)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'='*60}")
        print(f"  SAST Scan Results — {args.target}")
        print(f"{'='*60}")
        print(f"  Files scanned  : {result['files_scanned']}")
        print(f"  Total findings : {result['total']}")
        print(f"  Critical       : {result['critical']}")
        print(f"  High           : {result['high']}")
        print(f"  Medium         : {result['medium']}")
        print(f"  Low            : {result['low']}")
        print(f"  Info           : {result['info']}")
        print(f"{'='*60}\n")

        for finding in result["findings"]:
            print(f"  [{finding['severity'].upper()}] {finding['rule_id']} — {finding['title']}")
            print(f"    File: {finding['file']}:{finding['line']}")
            print(f"    Code: {finding['code_snippet']}")
            print(f"    Msg: {finding['message']}")
            if finding["reference"]:
                print(f"    Ref: {finding['reference']}")
            print()


if __name__ == "__main__":
    main()
