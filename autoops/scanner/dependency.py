"""
AutoSecOps — Dependency Scanner
Scans project dependency files (requirements.txt, package.json, go.mod, pom.xml)
for known vulnerabilities using the OSV (Open Source Vulnerabilities) API.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class VulnFinding:
    package: str
    version: str
    ecosystem: str           # PyPI, npm, Go, Maven, etc.
    vuln_id: str              # OSV ID, e.g. "OSV-2023-1842"
    severity: str             # critical / high / medium / low / unknown
    title: str
    message: str
    file: str                 # Which dependency file the package came from
    fixed_version: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Ecosystem Detection ────────────────────────────────────────────────────────

ECOSYSTEM_FILES = {
    "PyPI":     ["requirements.txt", "Pipfile", "Pipfile.lock", "setup.py"],
    "npm":      ["package.json", "package-lock.json"],
    "Go":       ["go.mod", "go.sum"],
    "Maven":    ["pom.xml", "build.gradle"],
    "Cargo":    ["Cargo.toml", "Cargo.lock"],
    "NuGet":    ["packages.config", "*.nuget"],
    "Ruby":     ["Gemfile", "Gemfile.lock"],
}

ECOSYSTEM_REPO = {
    "PyPI":   "https://pypi.org/pypi/{package}/json",
    "npm":    "https://registry.npmjs.org/{package}",
    "Go":     "https://pkg.go.dev/{package}?tab=versions",
    "Maven":  "https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}",
    "Cargo":  "https://crates.io/api/v1/crates/{package}",
}

OSV_API = "https://api.osv.dev/v1/query"

# ── Dependency Parser ──────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt and return list of (package, version) pairs."""
    pkgs = []
    if not path.exists():
        return pkgs
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, <=, ~=, != constraints
        m = re.match(r"([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=|!=|>|<)(.+)", line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2).strip()))
        else:
            # Unpinned
            pkgs.append((line.lower(), "latest"))
    return pkgs


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse package.json and return list of (package, version) pairs."""
    pkgs = []
    if not path.exists():
        return pkgs
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for pkg, ver in deps.items():
            # Strip semver range chars
            ver = re.sub(r"^[\^~>=<]+", "", ver)
            pkgs.append((pkg, ver))
    except Exception:
        pass
    return pkgs


def parse_go_mod(path: Path) -> list[tuple[str, str]]:
    """Parse go.mod and return list of (module, version) pairs."""
    pkgs = []
    if not path.exists():
        return pkgs
    in_require = False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                pkg = parts[0]
                ver = parts[1]
                pkgs.append((pkg, ver))
    return pkgs


def parse_pom_xml(path: Path) -> list[tuple[str, str]]:
    """Parse pom.xml for Maven dependencies (simplified)."""
    pkgs = []
    if not path.exists():
        return pkgs
    content = path.read_text(encoding="utf-8", errors="ignore")
    # Match <groupId>...</groupId> followed by <artifactId>...</artifactId>
    gids = re.findall(r"<groupId>([^<]+)</groupId>", content)
    aids = re.findall(r"<artifactId>([^<]+)</artifactId>", content)
    vers = re.findall(r"<version>([^<]+)</version>", content)
    for i, (gid, aid) in enumerate(zip(gids, aids)):
        ver = vers[i] if i < len(vers) else "unknown"
        pkgs.append((f"{gid}:{aid}", ver))
    return pkgs


def parse_deps(path: Path) -> list[tuple[str, str]]:
    """Auto-detect file type and parse dependencies."""
    name = path.name.lower()
    if name == "requirements.txt":
        return parse_requirements_txt(path)
    elif name == "package.json":
        return parse_package_json(path)
    elif name == "go.mod":
        return parse_go_mod(path)
    elif name == "pom.xml":
        return parse_pom_xml(path)
    return []


def detect_ecosystem(path: Path) -> str | None:
    """Detect ecosystem from filename."""
    name = path.name.lower()
    for eco, files in ECOSYSTEM_FILES.items():
        if name in [f.lower() for f in files]:
            return eco
    return None


# ── OSV API Client ─────────────────────────────────────────────────────────────

def query_osv(package: str, version: str, ecosystem: str) -> list[dict]:
    """
    Query OSV API for vulnerabilities affecting a specific package version.
    Returns list of OSV vulnerability records.
    """
    eco_map = {"PyPI": "PyPI", "npm": "npm", "Go": "Go", "Maven": "Maven", "Cargo": "Cargo"}
    osv_eco = eco_map.get(ecosystem, ecosystem)

    payload = json.dumps({
        "package": {"name": package, "ecosystem": osv_eco},
        "version": version,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            OSV_API,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except Exception as e:
        print(f"[dep] warn: OSV query failed for {ecosystem}:{package}@{version}: {e}", file=sys.stderr)
        return []


def severity_to_level(severity: str | None) -> str:
    """Normalize OSV severity to our scale."""
    if not severity:
        return "unknown"
    s = severity.lower()
    if s in ("critical", "critical"):
        return "critical"
    elif s in ("high",):
        return "high"
    elif s in ("medium", "moderate"):
        return "medium"
    elif s in ("low",):
        return "low"
    return "unknown"


# ── Dependency Scanner ────────────────────────────────────────────────────────

class DependencyScanner:
    """
    Scan dependency files for known vulnerabilities using OSV API.
    Supports: PyPI (requirements.txt), npm (package.json), Go (go.mod), Maven (pom.xml)
    """

    def __init__(
        self,
        fail_on: str = "critical",
        max_workers: int = 8,
        timeout_per_pkg: int = 15,
    ):
        self.fail_on = fail_on
        self.max_workers = max_workers
        self.timeout_per_pkg = timeout_per_pkg
        self._severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

    def scan(self, target_path: str | Path) -> dict:
        """
        Find all dependency files under target_path and scan each one.
        Returns aggregated results.
        """
        target = Path(target_path)
        all_findings: list[VulnFinding] = []
        dep_files_found: list[dict] = []

        for dep_file in self._find_dep_files(target):
            eco = detect_ecosystem(dep_file)
            if eco is None:
                continue
            deps = parse_deps(dep_file)
            dep_files_found.append({"file": str(dep_file), "ecosystem": eco, "count": len(deps)})
            self._scan_deps(deps, eco, str(dep_file), all_findings)

        all_findings.sort(key=lambda f: (self._severity_order.get(f.severity, 5), f.package))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "total": len(all_findings),
            "files_found": dep_files_found,
            **counts,
            "findings": [f.to_dict() for f in all_findings],
        }

    def _find_dep_files(self, root: Path):
        """Yield Path objects for known dependency files."""
        dep_names = {name for names in ECOSYSTEM_FILES.values() for name in names}
        if root.is_file():
            if root.name in dep_names:
                yield root
            return
        for dirpath, _, filenames in os.walk(root):
            # Skip node_modules, vendor, etc.
            dirnames = os.listdir(dirpath)
            if "node_modules" in dirnames or "vendor" in dirnames or ".venv" in dirnames:
                continue
            for fname in filenames:
                if fname in dep_names:
                    yield Path(dirpath) / fname

    def _scan_deps(
        self,
        deps: list[tuple[str, str]],
        ecosystem: str,
        file: str,
        findings: list[VulnFinding],
    ):
        """Query OSV for each dependency (parallel)."""
        from concurrent.futures import ThreadPoolExecutor

        def query_one(pkg: str, ver: str) -> list[VulnFinding]:
            vulns = query_osv(pkg, ver, ecosystem)
            results = []
            for v in vulns:
                severity = "unknown"
                title = ""
                message = ""
                fixed = ""
                reference = ""
                if isinstance(v.get("severity"), list):
                    for s in v["severity"]:
                        if s.get("type") == "CVSS_V3":
                            # Extract severity from CVSS score
                            score = float(s.get("score", "0"))
                            if score >= 9.0:
                                severity = "critical"
                            elif score >= 7.0:
                                severity = "high"
                            elif score >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"
                elif isinstance(v.get("severity"), dict):
                    score = float(v["severity"].get("score", "0"))
                    if score >= 9.0:
                        severity = "critical"
                    elif score >= 7.0:
                        severity = "high"
                    elif score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"

                title = v.get("summary", v.get("id", "Unknown vulnerability"))
                details = v.get("details", "")
                message = f"{title}. {details[:300]}" if details else title

                refs = v.get("references", [])
                if refs:
                    reference = refs[0].get("url", "")

                # Check for fixed version in affected ranges
                affected = v.get("affected", [])
                for aff in affected:
                    if aff.get("package", {}).get("name") == pkg:
                        for r in aff.get("ranges", []):
                            for e in r.get("events", []):
                                if e.get("fixed"):
                                    fixed = e["fixed"]
                                    break

                results.append(VulnFinding(
                    package=pkg,
                    version=ver,
                    ecosystem=ecosystem,
                    vuln_id=v.get("id", "?"),
                    severity=severity,
                    title=title,
                    message=message,
                    file=file,
                    fixed_version=fixed,
                    reference=reference,
                ))
            return results

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(query_one, p, v): (p, v) for p, v in deps}
            for future in futures:
                try:
                    for finding in future.result():
                        findings.append(finding)
                except Exception as e:
                    print(f"[dep] warn: error scanning {futures[future]}: {e}", file=sys.stderr)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="AutoSecOps Dependency Scanner")
    parser.add_argument("target", help="Directory or dependency file to scan")
    parser.add_argument("--fail-on", default="critical",
                        choices=["critical", "high", "medium", "low", "unknown"])
    parser.add_argument("--json", dest="output_json", action="store_true")
    args = parser.parse_args()

    scanner = DependencyScanner(fail_on=args.fail_on)
    result = scanner.scan(args.target)

    if args.output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'='*60}")
        print(f"  Dependency Audit Results — {args.target}")
        print(f"{'='*60}")
        print(f"  Files scanned : {len(result['files_found'])}")
        for f in result["files_found"]:
            print(f"    {f['ecosystem']}: {f['file']} ({f['count']} packages)")
        print(f"  Total vulns  : {result['total']}")
        print(f"  Critical     : {result['critical']}")
        print(f"  High         : {result['high']}")
        print(f"  Medium       : {result['medium']}")
        print(f"  Low          : {result['low']}")
        print(f"  Unknown      : {result['unknown']}")
        print(f"{'='*60}\n")

        for finding in result["findings"]:
            print(f"  [{finding['severity'].upper()}] {finding['vuln_id']} — {finding['title']}")
            print(f"    Package: {finding['package']}@{finding['version']} ({finding['ecosystem']})")
            if finding["fixed_version"]:
                print(f"    Fixed in: {finding['fixed_version']}")
            print(f"    Msg: {finding['message'][:200]}")
            if finding["reference"]:
                print(f"    Ref: {finding['reference']}")
            print()


if __name__ == "__main__":
    main()
