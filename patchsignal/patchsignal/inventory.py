"""Inventory: the customer's list of technology they care about, from a CSV."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import date

REQUIRED = ("asset", "vendor", "product")
OPTIONAL = (
    "version", "environment", "internet_exposed", "criticality",
    "owner_name", "owner_email", "team", "status", "exception_until", "exception_reason",
    "exposure", "human_impact", "escalate_to", "accountable", "oncall",
)
EXPOSURE_VALUES = {"small", "controlled", "open"}
HUMAN_IMPACT_VALUES = {"low", "medium", "high", "very high"}
TRUE_WORDS = {"yes", "y", "true", "1", "internet", "public", "external"}


@dataclass
class Asset:
    asset: str
    vendor: str
    product: str
    version: str = ""
    environment: str = "production"
    internet_exposed: bool = False
    criticality: str = "medium"
    owner_name: str = ""
    owner_email: str = ""
    team: str = ""
    status: str = "active"
    exception_until: date | None = None
    exception_reason: str = ""
    exposure: str = ""       # SSVC System Exposure override: small | controlled | open
    human_impact: str = ""   # SSVC Human Impact override: low | medium | high | very high
    escalate_to: str = ""    # hears about it only if it is stuck
    accountable: str = ""    # gets a one-line status, never the technical detail
    oncall: str = ""         # joins the fixer on Act now
    row: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def is_production(self) -> bool:
        return self.environment in {"production", "prod", "live"}

    @property
    def has_owner(self) -> bool:
        return bool(self.owner_email)


class InventoryError(ValueError):
    pass


def _norm_header(h: str) -> str:
    return h.strip().lower().replace(" ", "_").replace("-", "_")


def parse_inventory(text: str) -> list[Asset]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise InventoryError("The CSV has no header row.")
    headers = {_norm_header(h): h for h in reader.fieldnames if h}
    missing = [c for c in REQUIRED if c not in headers]
    if missing:
        raise InventoryError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Required: {', '.join(REQUIRED)}. Optional: {', '.join(OPTIONAL)}."
        )

    def get(rowd: dict, key: str) -> str:
        h = headers.get(key)
        return (rowd.get(h) or "").strip() if h else ""

    assets: list[Asset] = []
    for i, rowd in enumerate(reader, start=2):
        if not any((v or "").strip() for v in rowd.values()):
            continue
        a = Asset(
            asset=get(rowd, "asset"),
            vendor=get(rowd, "vendor"),
            product=get(rowd, "product"),
            version=get(rowd, "version"),
            environment=(get(rowd, "environment") or "production").lower(),
            internet_exposed=get(rowd, "internet_exposed").lower() in TRUE_WORDS,
            criticality=(get(rowd, "criticality") or "medium").lower(),
            owner_name=get(rowd, "owner_name"),
            owner_email=get(rowd, "owner_email").lower(),
            team=get(rowd, "team"),
            status=(get(rowd, "status") or "active").lower(),
            exception_reason=get(rowd, "exception_reason"),
            escalate_to=get(rowd, "escalate_to").lower(),
            accountable=get(rowd, "accountable").lower(),
            oncall=get(rowd, "oncall").lower(),
            row=i,
        )
        for col, allowed in (("exposure", EXPOSURE_VALUES), ("human_impact", HUMAN_IMPACT_VALUES)):
            val = get(rowd, col).lower().replace("_", " ")
            if val and val not in allowed:
                a.warnings.append(f"{col} '{val}' is not one of {', '.join(sorted(allowed))}; ignored")
            elif val:
                setattr(a, col, val)
        exc = get(rowd, "exception_until")
        if exc:
            try:
                a.exception_until = date.fromisoformat(exc)
            except ValueError:
                a.warnings.append(f"exception_until '{exc}' is not YYYY-MM-DD; ignored")
        if not a.asset or not a.product:
            a.warnings.append("asset or product is blank")
        if not a.vendor:
            a.warnings.append("vendor is blank; matching will be less certain")
        assets.append(a)
    if not assets:
        raise InventoryError("The CSV has a header but no rows.")
    return assets
