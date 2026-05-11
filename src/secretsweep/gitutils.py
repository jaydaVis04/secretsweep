from __future__ import annotations

import subprocess
from pathlib import Path


def is_git_repo(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def staged_files(path: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(path), "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Unable to list staged files")
    files: list[Path] = []
    for line in result.stdout.splitlines():
        candidate = (path / line).resolve()
        try:
            candidate.relative_to(path.resolve())
        except ValueError:
            continue
        if candidate.exists() and candidate.is_file():
            files.append(candidate)
    return files


def build_pre_commit_hook_script() -> str:
    return """#!/bin/sh
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if command -v mktemp >/dev/null 2>&1; then
  TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/secretsweep.XXXXXX.json")"
else
  TMP_FILE="${TMPDIR:-/tmp}/secretsweep.$$.json"
  : > "$TMP_FILE"
fi
cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT

if command -v secretsweep >/dev/null 2>&1; then
  SCAN_CMD="secretsweep scan . --staged --json --fail-on high"
elif [ -f "pyproject.toml" ] && [ -d "src/secretsweep" ] && command -v py >/dev/null 2>&1; then
  SCAN_CMD="PYTHONPATH=src py -m secretsweep scan . --staged --json --fail-on high"
elif [ -f "pyproject.toml" ] && [ -d "src/secretsweep" ] && command -v python >/dev/null 2>&1; then
  SCAN_CMD="PYTHONPATH=src python -m secretsweep scan . --staged --json --fail-on high"
elif [ -f "pyproject.toml" ] && [ -d "src/secretsweep" ] && command -v python3 >/dev/null 2>&1; then
  SCAN_CMD="PYTHONPATH=src python3 -m secretsweep scan . --staged --json --fail-on high"
else
  echo "secretsweep pre-commit hook could not find a runnable scanner."
  echo "Install the package or commit from the project root."
  exit 1
fi

if ! sh -c "$SCAN_CMD" > "$TMP_FILE"; then
  python3 - "$TMP_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

high = payload.get("summary", {}).get("high", 0)
if high:
    print("secretsweep blocked this commit due to HIGH severity findings.")
    for finding in payload.get("findings", []):
        if finding.get("severity") == "HIGH":
            print(f"- {finding['file']}:{finding['line']} [{finding['rule']}]")
    print("Resolve the findings or allowlist them before committing.")
else:
    print("secretsweep reported non-HIGH findings; commit will continue.")
    sys.exit(0)
PY
  status=$?
  if [ "$status" -ne 0 ]; then
    exit 1
  fi
fi
"""


def install_pre_commit_hook(repo_root: Path) -> Path:
    hook_dir = repo_root / ".git" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir / "pre-commit"
    hook_path.write_text(build_pre_commit_hook_script(), encoding="utf-8")
    hook_path.chmod(0o755)
    return hook_path
