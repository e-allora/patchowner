"""Notice state: what people did about a notice. Small JSON file, full history per notice.

Acknowledged is not remediated. Only 'fixed' and 'not_applicable' count as handled.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

ACTIONS = ("acknowledged", "assigned", "not_applicable", "fixed", "reopened")
HANDLED = {"fixed", "not_applicable"}
WORDS = {
    "acknowledged": "Acknowledged", "assigned": "Assigned", "not_applicable": "Does not apply",
    "fixed": "Fixed", "reopened": "Reopened",
}


@dataclass(frozen=True)
class Action:
    action: str
    by: str
    note: str
    at: str  # ISO 8601, UTC

    @property
    def word(self) -> str:
        return WORDS[self.action]

    @property
    def sentence(self) -> str:
        if self.action == "assigned":
            return f"Assigned to {self.note or 'someone'} by {self.by}."
        if self.action == "not_applicable":
            return f"{self.by} said this does not apply" + (f": {self.note}." if self.note else ".")
        return f"{self.word} by {self.by}" + (f": {self.note}." if self.note else ".")


def notice_key(cve_id: str, asset: str) -> str:
    return f"{cve_id}|{asset}"


class StateStore:
    def __init__(self, path: Path | str | None):
        self.path = Path(path) if path else None
        self.data: dict[str, list[Action]] = {}
        if self.path and self.path.exists():
            raw = json.loads(self.path.read_text() or "{}")
            self.data = {k: [Action(**a) for a in v] for k, v in raw.items()}

    def record(self, key: str, action: str, by: str, note: str = "", at: datetime | None = None) -> Action:
        if action not in ACTIONS:
            raise ValueError(f"'{action}' is not one of {', '.join(ACTIONS)}")
        a = Action(action, by.strip() or "someone", note.strip(), (at or datetime.now(timezone.utc)).isoformat(timespec="seconds"))
        self.data.setdefault(key, []).append(a)
        self.save()
        return a

    def current(self, key: str) -> Action | None:
        hist = self.data.get(key)
        if not hist:
            return None
        last = hist[-1]
        return None if last.action == "reopened" else last

    def history(self, key: str) -> list[Action]:
        return list(self.data.get(key, []))

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({k: [asdict(a) for a in v] for k, v in self.data.items()}, indent=1))
