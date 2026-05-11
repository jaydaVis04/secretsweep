from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


DEFAULT_EXCLUDES = ["vendor/", "node_modules/", "*.lock", "*.sum", ".git/", "__pycache__/", "build/", "dist/"]
DEFAULT_RULES = {
    "aws": True,
    "github": True,
    "slack": True,
    "jwt": True,
    "database_urls": True,
    "private_keys": True,
    "generic_api_keys": True,
    "high_entropy": True,
}

STARTER_CONFIG = """[scan]
entropy_threshold = 4.5
min_secret_length = 20
exclude_paths = ["vendor/", "node_modules/", "*.lock", "*.sum", "__pycache__/", "build/", "dist/"]

[allowlist]
patterns = [
  "example\\\\.com",
  "placeholder_key"
]
files = [
  "tests/fixtures/fake_credentials.env"
]

[rules]
aws = true
github = true
slack = true
jwt = true
database_urls = true
private_keys = true
generic_api_keys = true
high_entropy = true
"""


@dataclass(slots=True)
class Config:
    entropy_threshold: float = 4.5
    min_secret_length: int = 20
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    allowlist_patterns: list[str] = field(default_factory=list)
    allowlist_files: list[str] = field(default_factory=list)
    rules: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_RULES))

    def merge(self, payload: dict[str, Any]) -> None:
        scan = payload.get("scan", {})
        allowlist = payload.get("allowlist", {})
        rules = payload.get("rules", {})

        if "entropy_threshold" in scan:
            self.entropy_threshold = float(scan["entropy_threshold"])
        if "min_secret_length" in scan:
            self.min_secret_length = int(scan["min_secret_length"])
        if "exclude_paths" in scan:
            self.exclude_paths.extend(str(item) for item in scan["exclude_paths"])
        if "patterns" in allowlist:
            self.allowlist_patterns.extend(str(item) for item in allowlist["patterns"])
        if "files" in allowlist:
            self.allowlist_files.extend(str(item) for item in allowlist["files"])
        if rules:
            for key, value in rules.items():
                if key in self.rules:
                    self.rules[key] = bool(value)


def load_structured_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".toml":
        if tomllib is None:
            raise RuntimeError("TOML support requires Python 3.11+")
        return tomllib.loads(text)
    if suffix in {".yaml", ".yml"}:
        loaded = parse_simple_yaml(text)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a top-level mapping")
        return loaded
    if suffix == ".json":
        loaded = json.loads(text)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a top-level object")
        return loaded
    raise ValueError(f"Unsupported config format: {path.suffix}")


def parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]

    for index, raw_line in enumerate(lines):
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()
        container = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(container, list):
                raise ValueError("Unsupported YAML structure")
            container.append(_parse_scalar(line[2:].strip()))
            continue

        if ":" not in line or not isinstance(container, dict):
            raise ValueError("Unsupported YAML structure")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            next_line = lines[index + 1] if index + 1 < len(lines) else ""
            next_stripped = next_line.strip()
            new_container: dict[str, Any] | list[Any]
            if next_stripped.startswith("- "):
                new_container = []
            else:
                new_container = {}
            container[key] = new_container
            stack.append((indent, new_container))
            continue
        container[key] = _parse_scalar(value)

    return root


def _parse_scalar(value: str) -> Any:
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        return value[1:-1]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lower() in {"null", "none"}:
        return None
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def discover_config(scan_root: Path) -> Path | None:
    candidates = [
        scan_root / "secretsweep.toml",
        scan_root / ".secretsweep.toml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def load_config(scan_root: Path, allowlist_file: Path | None = None) -> Config:
    config = Config()
    config_path = discover_config(scan_root)
    if config_path is not None:
        config.merge(load_structured_file(config_path))
    if allowlist_file is not None:
        allowlist_payload = load_structured_file(allowlist_file)
        if "allowlist" in allowlist_payload:
            config.merge({"allowlist": allowlist_payload["allowlist"]})
        else:
            config.merge({"allowlist": allowlist_payload})
    return config


def path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    for pattern in patterns:
        token = pattern.replace("\\", "/")
        if token.endswith("/") and normalized.startswith(token):
            return True
        if fnmatch.fnmatch(normalized, token):
            return True
        if normalized == token:
            return True
    return False
