from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from .config import Config, path_matches_any
from .models import Finding, SEVERITY_RANK


TEXT_EXTENSIONS = {
    ".env",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".go",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    ".cfg",
    ".conf",
    ".sh",
    ".zsh",
    ".bash",
}
CONFIG_LIKE_EXTENSIONS = {".env", ".ini", ".json", ".toml", ".yaml", ".yml", ".cfg", ".conf"}

SENSITIVE_NAME_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|token|private[_-]?key|client[_-]?secret|db[_-]?url)\b"
)
ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z_][A-Za-z0-9_\-]{1,80})
    \s*[:=]\s*
    (?:
      "(?P<dq>[^"\n#]{3,})"
      |
      '(?P<sq>[^'\n#]{3,})'
      |
      (?P<bare>[A-Za-z0-9_\-\/+=:.@]{3,})
    )
    \s*$
    """
)
GENERIC_SECRET_RE = re.compile(
    r"""(?ix)
    \b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b
    \s*[:=]\s*
    ["']?(?P<value>[A-Za-z0-9_\-\/+=:.]{8,})["']?
    """
)


@dataclass(slots=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    recommendation: list[str]
    config_key: str | None = None


RULES = [
    Rule(
        name="aws-access-key",
        severity="HIGH",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        message="Possible AWS access key detected",
        recommendation=["Rotate this credential immediately", "Move it to a secrets manager", "Remove it from source control"],
        config_key="aws",
    ),
    Rule(
        name="github-token",
        severity="HIGH",
        pattern=re.compile(r"\b(?:ghp|gho|ghs)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        message="Possible GitHub token detected",
        recommendation=["Revoke this token", "Create a replacement with least privilege", "Store it outside the repository"],
        config_key="github",
    ),
    Rule(
        name="slack-token",
        severity="HIGH",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        message="Possible Slack token detected",
        recommendation=["Rotate this token immediately", "Limit token scopes", "Store it outside version control"],
        config_key="slack",
    ),
    Rule(
        name="private-key",
        severity="HIGH",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        message="Private key material detected",
        recommendation=["Treat this key as compromised", "Replace it with a newly generated key", "Remove it from the repository history"],
        config_key="private_keys",
    ),
    Rule(
        name="jwt",
        severity="HIGH",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        message="JWT detected",
        recommendation=["Confirm this token is not valid", "Rotate the backing credentials if it is active", "Use environment injection instead of hardcoding"],
        config_key="jwt",
    ),
    Rule(
        name="database-url",
        severity="HIGH",
        pattern=re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"<>]+"),
        message="Possible database URL detected",
        recommendation=["Rotate this credential immediately", "Move it to a secrets manager", "Add the source file to ignore rules if appropriate"],
        config_key="database_urls",
    ),
    Rule(
        name="generic-api-key",
        severity="HIGH",
        pattern=GENERIC_SECRET_RE,
        message="Generic API credential pattern detected",
        recommendation=["Verify whether this value is live", "Rotate it if active", "Move it into a secret store or environment variable"],
        config_key="generic_api_keys",
    ),
]


class ScanStats:
    def __init__(self) -> None:
        self.scanned_files = 0
        self.scanned_paths: list[str] = []
        self.skipped_files: list[tuple[str, str]] = []


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def redact_text(text: str, findings: list[Finding]) -> str:
    output = text
    for finding in sorted(findings, key=lambda item: len(item.match), reverse=True):
        output = output.replace(finding.match, "[REDACTED]")
    return output


def file_looks_binary(path: Path) -> bool:
    with path.open("rb") as handle:
        chunk = handle.read(2048)
    if b"\x00" in chunk:
        return True
    return False


def should_skip_file(root: Path, path: Path, config: Config) -> str | None:
    relative = path.relative_to(root).as_posix()
    if path_matches_any(relative, config.allowlist_files):
        return "allowlisted file"
    if path_matches_any(relative, config.exclude_paths):
        return "excluded by config"
    if path.name == ".git":
        return "git metadata"
    return None


def iter_files(root: Path, config: Config, verbose: bool = False) -> tuple[list[Path], ScanStats]:
    stats = ScanStats()
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        reason = should_skip_file(root, path, config)
        if reason is not None:
            if verbose:
                stats.skipped_files.append((path.relative_to(root).as_posix(), reason))
            continue
        files.append(path)
    return files, stats


def apply_baseline(findings: list[Finding], baseline_path: Path | None) -> list[Finding]:
    if baseline_path is None or not baseline_path.exists():
        return findings
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    existing = {
        (
            item.get("file", ""),
            int(item.get("line", 0)),
            item.get("rule", ""),
            item.get("match", ""),
        )
        for item in payload.get("findings", [])
    }
    return [finding for finding in findings if finding.baseline_key() not in existing]


def is_allowlisted(config: Config, relative_path: str, candidate: str) -> bool:
    if path_matches_any(relative_path, config.allowlist_files):
        return True
    for pattern in config.allowlist_patterns:
        if re.search(pattern, candidate):
            return True
    return False


def enabled_rules(config: Config) -> list[Rule]:
    output: list[Rule] = []
    for rule in RULES:
        if rule.config_key is None or config.rules.get(rule.config_key, True):
            output.append(rule)
    return output


def scan_line(relative_path: str, line_no: int, line: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for rule in enabled_rules(config):
        for match in rule.pattern.finditer(line):
            matched = match.group(0)
            if is_allowlisted(config, relative_path, matched):
                continue
            findings.append(
                Finding(
                    severity=rule.severity,
                    file=relative_path,
                    line=line_no,
                    rule=rule.name,
                    match=matched,
                    message=rule.message,
                    recommendation=rule.recommendation,
                )
            )
    assignment = ASSIGNMENT_RE.search(line.strip())
    if assignment:
        name = assignment.group("name")
        value = assignment.group("dq") or assignment.group("sq") or assignment.group("bare") or ""
        if value and not is_allowlisted(config, relative_path, value):
            config_like = is_config_file(relative_path)
            sensitive_name = bool(SENSITIVE_NAME_RE.search(name))
            source_sensitive = sensitive_name and name.isupper()
            if (config_like or source_sensitive) and sensitive_name and not any(
                finding.rule in {"generic-api-key", "database-url"} for finding in findings
            ):
                findings.append(
                    Finding(
                        severity="LOW",
                        file=relative_path,
                        line=line_no,
                        rule="sensitive-assignment",
                        match=value,
                        message="Suspicious variable name with a non-empty value",
                        recommendation=["Confirm this value is safe to commit", "Prefer environment injection for real secrets"],
                    )
                )
            if (
                config.rules.get("high_entropy", True)
                and (config_like or source_sensitive)
                and len(value) >= config.min_secret_length
                and sensitive_name
            ):
                entropy = shannon_entropy(value)
                if entropy >= config.entropy_threshold:
                    findings.append(
                        Finding(
                            severity="MEDIUM",
                            file=relative_path,
                            line=line_no,
                            rule="high-entropy",
                            match=value,
                            message="High-entropy string in variable assignment",
                            recommendation=["Confirm this is not a real credential", "If legitimate, add it to the allowlist"],
                            entropy=round(entropy, 2),
                        )
                    )
    return findings


def is_config_file(relative_path: str) -> bool:
    path = Path(relative_path)
    suffix = path.suffix.lower()
    if suffix in CONFIG_LIKE_EXTENSIONS:
        return True
    if path.name.startswith(".env"):
        return True
    return False


def scan_file(root: Path, path: Path, config: Config, stats: ScanStats, verbose: bool = False) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    if file_looks_binary(path):
        if verbose:
            stats.skipped_files.append((relative, "binary file"))
        return []
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.stat().st_size > 1_000_000:
        if verbose:
            stats.skipped_files.append((relative, "large non-text file"))
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    stats.scanned_files += 1
    if verbose:
        stats.scanned_paths.append(relative)
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(relative, line_no, line, config))
    deduped: dict[tuple[str, int, str, str], Finding] = {}
    for finding in findings:
        current = deduped.get(finding.baseline_key())
        if current is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current.severity]:
            deduped[finding.baseline_key()] = finding
    return list(deduped.values())


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        summary[finding.severity.lower()] += 1
    return summary
