from __future__ import annotations

from dataclasses import asdict, dataclass


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass(slots=True)
class Finding:
    severity: str
    file: str
    line: int
    rule: str
    match: str
    message: str
    recommendation: list[str]
    entropy: float | None = None

    def to_json(self) -> dict:
        payload = asdict(self)
        if self.entropy is None:
            payload.pop("entropy", None)
        return payload

    def baseline_key(self) -> tuple[str, int, str, str]:
        return (self.file, self.line, self.rule, self.match)
