from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import STARTER_CONFIG, discover_config, load_config
from .gitutils import install_pre_commit_hook, is_git_repo, staged_files
from .models import Finding, SEVERITY_RANK
from .scanner import RULES, apply_baseline, iter_files, redact_text, scan_file, summarize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretsweep", description="Local-first CLI secret scanner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for secrets")
    scan_parser.add_argument("target", help="Directory or file to scan")
    scan_parser.add_argument("--staged", action="store_true", help="Scan only git-staged files")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable findings")
    scan_parser.add_argument("--entropy", type=float, help="Override the entropy threshold")
    scan_parser.add_argument("--allowlist", type=Path, help="Path to a TOML/YAML/JSON allowlist file")
    scan_parser.add_argument("--baseline", type=Path, help="Path to a baseline JSON file")
    scan_parser.add_argument("--write-baseline", type=Path, help="Write current findings to a baseline JSON file")
    scan_parser.add_argument("--no-git", action="store_true", help="Scan without git-aware behavior")
    scan_parser.add_argument("--verbose", action="store_true", help="Show scanned and skipped files")
    scan_parser.add_argument("--redact", action="store_true", help="Redact matched values in-place")
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high"], default="low", help=argparse.SUPPRESS)

    redact_parser = subparsers.add_parser("redact", help="Redact secrets in a file in-place")
    redact_parser.add_argument("target", help="File to redact")
    redact_parser.add_argument("--entropy", type=float, help="Override the entropy threshold")
    redact_parser.add_argument("--allowlist", type=Path, help="Path to a TOML/YAML/JSON allowlist file")

    subparsers.add_parser("install-hook", help="Install a git pre-commit hook")
    doctor_parser = subparsers.add_parser("doctor", help="Inspect local environment and repo readiness")
    doctor_parser.add_argument("target", nargs="?", default=".", help="Directory to inspect")
    doctor_parser.add_argument("--json", action="store_true", help="Output JSON diagnostics")
    init_parser = subparsers.add_parser("init", help="Generate a starter secretsweep.toml")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing config")
    return parser


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (-SEVERITY_RANK[item.severity], item.file, item.line, item.rule))


def collect_targets(target: Path, staged: bool, no_git: bool, config, verbose: bool) -> tuple[Path, list[Path], object]:
    scan_root = target if target.is_dir() else target.parent
    if staged:
        if no_git:
            raise RuntimeError("--staged cannot be used with --no-git")
        if not is_git_repo(scan_root):
            raise RuntimeError("--staged requires a git repository")
        files = staged_files(scan_root)
        stats = type("Stats", (), {"scanned_files": 0, "scanned_paths": [], "skipped_files": []})()
        return scan_root.resolve(), files, stats
    if target.is_file():
        stats = type("Stats", (), {"scanned_files": 0, "scanned_paths": [], "skipped_files": []})()
        return scan_root.resolve(), [target.resolve()], stats
    files, stats = iter_files(target.resolve(), config, verbose=verbose)
    return target.resolve(), files, stats


def print_human(
    findings: list[Finding],
    scanned_files: int,
    scanned_paths: list[str],
    skipped: list[tuple[str, str]],
    verbose: bool,
) -> None:
    print(f"Scanning {scanned_files} files...")
    if verbose and (scanned_paths or skipped):
        print()
        for path in scanned_paths:
            print(f"SCAN {path}")
        for path, reason in skipped:
            print(f"SKIP {path} ({reason})")
    if not findings:
        print()
        print("No findings.")
        return
    for finding in findings:
        print()
        print("──────────────────────────────────────────────")
        print(f" {finding.severity}  {finding.file}:{finding.line}")
        print("──────────────────────────────────────────────")
        detail = finding.message
        if finding.entropy is not None:
            detail = f"{detail} (entropy: {finding.entropy})"
        print(detail)
        print()
        print(f" {finding.match}")
        print()
        print(" Recommendation:")
        for item in finding.recommendation:
            print(f"   - {item}")
    summary = summarize(findings)
    print()
    print("──────────────────────────────────────────────")
    print(f" {len(findings)} findings ({summary['high']} HIGH, {summary['medium']} MEDIUM, {summary['low']} LOW)")
    print(" Run with --json for CI output or use `secretsweep redact <file>` to sanitize files.")


def print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2))


def build_rule_catalog() -> dict[str, dict]:
    return {
        rule.name: {
            "severity": rule.severity,
            "message": rule.message,
            "recommendation": rule.recommendation,
        }
        for rule in RULES
    }


def build_json_payload(findings: list[Finding], scanned_files: int, metadata: dict | None = None) -> dict:
    return {
        "scanned_files": scanned_files,
        "findings": [finding.to_json() for finding in findings],
        "summary": summarize(findings),
        "metadata": metadata or {},
        "rules": build_rule_catalog(),
    }


def should_fail(findings: list[Finding], threshold: str) -> bool:
    cutoff = threshold.upper()
    return any(SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[cutoff] for finding in findings)


def build_doctor_payload(target: Path) -> dict:
    resolved = target.resolve()
    scan_root = resolved if resolved.is_dir() else resolved.parent
    config_path = discover_config(scan_root)
    return {
        "version": __version__,
        "target": str(resolved),
        "scan_root": str(scan_root),
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
        },
        "commands": {
            "git": shutil.which("git"),
            "secretsweep": shutil.which("secretsweep"),
            "python": shutil.which("python"),
            "python3": shutil.which("python3"),
            "py": shutil.which("py"),
        },
        "git": {
            "inside_repo": is_git_repo(scan_root),
            "hooks_path": str(scan_root / ".git" / "hooks"),
        },
        "config": {
            "found": config_path is not None,
            "path": str(config_path) if config_path is not None else None,
        },
    }


def print_doctor_human(payload: dict) -> None:
    print(f"secretsweep {payload['version']}")
    print(f"Target: {payload['target']}")
    print(f"Scan root: {payload['scan_root']}")
    print(f"Python: {payload['python']['version']} ({payload['python']['executable']})")
    print(f"Git command: {payload['commands']['git'] or 'not found'}")
    print(f"secretsweep command: {payload['commands']['secretsweep'] or 'not found'}")
    print(f"Git repo: {'yes' if payload['git']['inside_repo'] else 'no'}")
    print(f"Config: {payload['config']['path'] or 'not found'}")


def command_scan(args: argparse.Namespace) -> int:
    started_at = datetime.now(UTC)
    started_counter = time.perf_counter()
    target = Path(args.target).resolve()
    if not target.exists():
        raise RuntimeError(f"Target does not exist: {target}")
    config = load_config(target if target.is_dir() else target.parent, args.allowlist)
    if args.entropy is not None:
        config.entropy_threshold = args.entropy

    scan_root, files, stats = collect_targets(target, args.staged, args.no_git, config, args.verbose)
    skip_paths = {
        path.resolve()
        for path in [args.allowlist, args.baseline]
        if path is not None and path.exists()
    }
    if skip_paths:
        filtered_files: list[Path] = []
        for path in files:
            if path.resolve() in skip_paths:
                if args.verbose:
                    stats.skipped_files.append((path.relative_to(scan_root).as_posix(), "auxiliary scan input"))
                continue
            filtered_files.append(path)
        files = filtered_files
    findings: list[Finding] = []
    for path in files:
        findings.extend(scan_file(scan_root, path, config, stats, verbose=args.verbose))
    findings = sort_findings(apply_baseline(findings, args.baseline))

    if args.redact:
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file, []).append(finding)
        for relative, file_findings in by_file.items():
            path = scan_root / relative
            text = path.read_text(encoding="utf-8", errors="ignore")
            path.write_text(redact_text(text, file_findings), encoding="utf-8")

    duration_ms = round((time.perf_counter() - started_counter) * 1000, 2)
    payload = build_json_payload(
        findings,
        stats.scanned_files,
        metadata={
            "version": __version__,
            "target": str(target),
            "scan_root": str(scan_root),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
            "entropy_threshold": config.entropy_threshold,
            "min_secret_length": config.min_secret_length,
            "staged": args.staged,
            "baseline_applied": str(args.baseline) if args.baseline else None,
            "allowlist_applied": str(args.allowlist) if args.allowlist else None,
            "redacted": args.redact,
        },
    )

    if args.json:
        print_json(payload)
    else:
        print_human(findings, stats.scanned_files, stats.scanned_paths, stats.skipped_files, args.verbose)

    if args.write_baseline is not None:
        args.write_baseline.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return 1 if should_fail(findings, args.fail_on) else 0


def command_redact(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists() or not target.is_file():
        raise RuntimeError("redact requires a file target")
    config = load_config(target.parent, args.allowlist)
    if args.entropy is not None:
        config.entropy_threshold = args.entropy
    stats = type("Stats", (), {"scanned_files": 0, "skipped_files": []})()
    findings = sort_findings(scan_file(target.parent, target, config, stats))
    if not findings:
        print(f"No findings in {target.name}.")
        return 0
    text = target.read_text(encoding="utf-8", errors="ignore")
    target.write_text(redact_text(text, findings), encoding="utf-8")
    print(f"Redacted {len(findings)} finding(s) in {target}.")
    return 0


def command_install_hook() -> int:
    repo_root = Path.cwd().resolve()
    if not is_git_repo(repo_root):
        raise RuntimeError("install-hook must be run inside a git repository")
    hook_path = install_pre_commit_hook(repo_root)
    print(f"Installed pre-commit hook at {hook_path}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        raise RuntimeError(f"Target does not exist: {target}")
    payload = build_doctor_payload(target)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_doctor_human(payload)
    return 0


def command_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / "secretsweep.toml"
    if target.exists() and not args.force:
        raise RuntimeError(f"{target} already exists. Use --force to overwrite it.")
    target.write_text(STARTER_CONFIG, encoding="utf-8")
    print(f"Wrote starter config to {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return command_scan(args)
        if args.command == "redact":
            return command_redact(args)
        if args.command == "install-hook":
            return command_install_hook()
        if args.command == "doctor":
            return command_doctor(args)
        if args.command == "init":
            return command_init(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
