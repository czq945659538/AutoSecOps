"""
AutoSecOps — CLI Entry Point
Unified command-line interface for all scanner modules.
Usage: autoops <command> [options]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Add parent dir to path so subpackages can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

from autoops.scanner.sast import SASTScanner
from autoops.scanner.dependency import DependencyScanner
from autoops.scanner.secret import SecretScanner
from autoops.scanner.container import ContainerScanner
from autoops.scanner.compliance import ComplianceScanner
from autoops.engine.report import ReportEngine
from autoops.storage.db import get_db


def cmd_scan(args):
    """Run one or more scanners and generate a report."""
    target = args.target
    scan_types = args.types or ["sast", "dependency", "secret"]
    fail_on = args.fail_on or "medium"
    output_dir = args.output_dir or "autoops-reports"

    if not Path(target).exists():
        print(f"Error: target not found: {target}")
        sys.exit(1)

    results = {}
    scan_id = args.scan_id or str(int(time.time()))
    started_at = time.time()

    print(f"\n[AutoSecOps] Starting scan {scan_id}")
    print(f"  Target : {target}")
    print(f"  Types  : {scan_types}")
    print(f"  Fail-on: {fail_on}\n")

    # ── SAST ────────────────────────────────────────────────────────
    if "sast" in scan_types:
        print("[1/3] Running SAST scanner...")
        try:
            scanner = SASTScanner(
                languages=args.languages,
                severity_threshold=fail_on,
                exclude_paths=args.exclude or [],
            )
            results["sast"] = scanner.scan(target)
            s = results["sast"]
            print(f"  → {s['files_scanned']} files scanned, {s['total']} findings "
                  f"(C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']})")
        except Exception as e:
            print(f"  → SAST failed: {e}")
            results["sast"] = {"total": 0, "files_scanned": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": []}

    # ── Dependency ──────────────────────────────────────────────────
    if "dependency" in scan_types:
        print("[2/3] Running dependency audit...")
        try:
            scanner = DependencyScanner(fail_on=fail_on)
            results["dependency"] = scanner.scan(target)
            d = results["dependency"]
            print(f"  → {d['total']} vulnerabilities found "
                  f"(C:{d['critical']} H:{d['high']} M:{d['medium']} L:{d['low']})")
        except Exception as e:
            print(f"  → Dependency scan failed: {e}")
            results["dependency"] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": []}

    # ── Secret ─────────────────────────────────────────────────────
    if "secret" in scan_types:
        print("[3/3] Running secret scanner...")
        try:
            scanner = SecretScanner(exclude_paths=args.exclude or [])
            results["secret"] = scanner.scan(target)
            s = results["secret"]
            print(f"  → {s['files_scanned']} files scanned, {s['total']} secrets "
                  f"(C:{s['critical']} H:{s['high']} M:{s['medium']})")
        except Exception as e:
            print(f"  → Secret scan failed: {e}")
            results["secret"] = {"total": 0, "files_scanned": 0, "critical": 0, "high": 0, "medium": 0, "findings": []}

    elapsed = time.time() - started_at

    # ── Summary ──────────────────────────────────────────────────────
    all_findings = (
        results.get("sast", {}).get("findings", []) +
        results.get("dependency", {}).get("findings", []) +
        results.get("secret", {}).get("findings", [])
    )
    total_critical = sum(r.get("critical", 0) for r in results.values())
    total_high = sum(r.get("high", 0) for r in results.values())
    total = sum(r.get("total", 0) for r in results.values())

    print(f"\n{'='*60}")
    print(f"  Scan completed in {elapsed:.1f}s")
    print(f"  Total: {total} | Critical: {total_critical} | High: {total_high}")
    print(f"{'='*60}\n")

    # ── Report generation ────────────────────────────────────────────
    report_engine = ReportEngine(output_dir=output_dir)
    summary_data = {
        "total": total,
        "critical": total_critical,
        "high": total_high,
        "medium": sum(r.get("medium", 0) for r in results.values()),
        "low": sum(r.get("low", 0) for r in results.values()),
    }

    report_data = {
        "scan_id": scan_id,
        "target": target,
        "types": scan_types,
        "summary": summary_data,
        "sast_findings": results.get("sast", {}).get("findings", []),
        "dep_findings": results.get("dependency", {}).get("findings", []),
        "secret_findings": results.get("secret", {}).get("findings", []),
        "container_findings": [],
    }

    paths = report_engine.generate(scan_id, report_data)
    print(f"  Report: {paths['json']}")
    print(f"  HTML  : {paths['html']}")

    # ── Save to DB ───────────────────────────────────────────────────
    try:
        db = get_db()
        db.create_scan(scan_id, ",".join(scan_types), target, {"fail_on": fail_on, "exclude": args.exclude})
        db.update_scan(scan_id, status="completed", summary=summary_data,
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
        print(f"  Saved to DB: {db.db_path}")
    except Exception as e:
        print(f"  DB save warning: {e}")

    # ── Fail on threshold ───────────────────────────────────────────
    severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fail_idx = severity_map.get(fail_on, 4)
    max_found = severity_map.get(
        "critical" if total_critical else "high" if total_high else "info", 4
    )
    if max_found <= fail_idx:
        print(f"\n[FAIL] Scan found {total_critical} critical / {total_high} high issues (fail-on={fail_on})")
        sys.exit(1)
    else:
        print(f"\n[PASS] No issues above {fail_on} threshold")


def cmd_container(args):
    """Scan a Docker image."""
    scanner = ContainerScanner(scanner=args.scanner, severity_threshold=args.severity)
    print(f"Scanning image: {args.image}")
    result = scanner.scan(args.image)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("critical", 0) > 0 or result.get("high", 0) > 0:
        sys.exit(1)


def cmd_compliance(args):
    """Check compliance against CIS benchmarks."""
    scanner = ComplianceScanner(benchmark=args.benchmark)
    result = scanner.scan(args.target)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("critical", 0) > 0 or result.get("high", 0) > 0:
        sys.exit(1)


def cmd_history(args):
    """Show scan history from the database."""
    db = get_db()
    scans = db.list_scans(limit=args.limit)
    if not scans:
        print("No scans found.")
        return
    print(f"\n{'ID':<12} {'TYPE':<12} {'TARGET':<30} {'STATUS':<12} {'CREATED':<25}")
    print("-" * 95)
    for s in scans:
        summary = s.get("summary") or {}
        total = summary.get("total", "-")
        print(f"{s['id']:<12} {s['scan_type']:<12} {s['target']:<30} "
              f"{s['status']:<12} {s.get('created_at', ''):<25} [{total}]")


def main():
    parser = argparse.ArgumentParser(
        prog="autoops",
        description="AutoSecOps — Automated Ops & Security Platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Run security scan")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--types", nargs="+",
                        choices=["sast", "dependency", "secret", "container", "compliance", "full"],
                        help="Scan types to run")
    p_scan.add_argument("--fail-on", dest="fail_on",
                        choices=["critical", "high", "medium", "low"],
                        default="high", help="Exit with error if issues at or above this level")
    p_scan.add_argument("--languages", nargs="+",
                        choices=["python", "go", "javascript", "java", "nodejs"],
                        help="Languages for SAST")
    p_scan.add_argument("--exclude", nargs="+", help="Paths to exclude")
    p_scan.add_argument("--output-dir", dest="output_dir", default="autoops-reports")
    p_scan.add_argument("--scan-id", dest="scan_id", help="Override scan ID")
    p_scan.set_defaults(func=cmd_scan)

    # ── container ────────────────────────────────────────────────────
    p_cont = sub.add_parser("container", help="Scan Docker image")
    p_cont.add_argument("image", help="Docker image name")
    p_cont.add_argument("--scanner", default="trivy", choices=["trivy", "grype"])
    p_cont.add_argument("--severity", default="high")
    p_cont.set_defaults(func=cmd_container)

    # ── compliance ────────────────────────────────────────────────────
    p_comp = sub.add_parser("compliance", help="Check CIS compliance")
    p_comp.add_argument("target", help="Dockerfile or K8s manifest path")
    p_comp.add_argument("--benchmark", default="cis-docker",
                        choices=["cis-docker", "cis-k8s"])
    p_comp.set_defaults(func=cmd_compliance)

    # ── history ──────────────────────────────────────────────────────
    p_hist = sub.add_parser("history", help="Show scan history")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.set_defaults(func=cmd_history)

    args = parser.parse_args()

    # Handle "full" as alias for all types
    if hasattr(args, "types") and args.types and "full" in args.types:
        args.types = ["sast", "dependency", "secret"]

    args.func(args)


if __name__ == "__main__":
    main()
