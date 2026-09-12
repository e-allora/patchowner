"""SSVC: Stakeholder-Specific Vulnerability Categorization, deployer tree.

Decision points and their values are the SEI/CERT vocabulary and are not customizable.
The outcome label on each row of a policy is the organization's risk appetite and is.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

from .inventory import Asset
from .kev import Advisory

POLICY_DIR = Path(__file__).parent / "policies"
DEFAULT_POLICY = POLICY_DIR / "deployer_default.csv"


@dataclass(frozen=True)
class DecisionPoint:
    name: str                    # SSVC name, fixed vocabulary, shown to auditors
    key: str                     # abbreviated-vector key per SSVC v2 "Communication Formats"
    values: tuple[str, ...]      # SSVC values, fixed vocabulary
    abbrev: dict[str, str]
    question: str                # the same question in plain words, shown to people
    plain: dict[str, str]        # SSVC value -> plain words
    clause: dict[str, str]       # SSVC value -> "because ..." clause for one-sentence explanations

    def word(self, value: str) -> str:
        return self.plain[value]


EXPLOITATION = DecisionPoint(
    "Exploitation", "E", ("none", "public poc", "active"), {"none": "N", "public poc": "P", "active": "A"},
    "Is it being attacked?", {"none": "no", "public poc": "a proof exists", "active": "yes, right now"},
    {"none": "nobody is attacking it", "public poc": "a public proof of attack exists", "active": "attackers are using it right now"},
)
EXPOSURE = DecisionPoint(
    "System Exposure", "Se", ("small", "controlled", "open"), {"small": "S", "controlled": "C", "open": "O"},
    "Can attackers reach it?", {"small": "isolated", "controlled": "from inside only", "open": "from the internet"},
    {"small": "it's isolated", "controlled": "it's reachable only from inside", "open": "it's reachable from the internet"},
)
AUTOMATABLE = DecisionPoint(
    "Automatable", "A", ("no", "yes"), {"no": "N", "yes": "Y"},
    "Can the attack run by itself?", {"no": "no, it needs a person", "yes": "yes"},
    {"no": "the attack needs a person's help", "yes": "the attack can run by itself"},
)
HUMAN_IMPACT = DecisionPoint(
    "Human Impact", "H", ("low", "medium", "high", "very high"), {"low": "L", "medium": "M", "high": "H", "very high": "Vh"},
    "How much would it hurt?", {"low": "a little", "medium": "some", "high": "a lot", "very high": "business-stopping"},
    {"low": "it would hurt a little", "medium": "it would hurt some", "high": "it would hurt a lot", "very high": "it could stop the business"},
)
POINTS: tuple[DecisionPoint, ...] = (EXPLOITATION, EXPOSURE, AUTOMATABLE, HUMAN_IMPACT)
OUTCOMES: tuple[str, ...] = ("defer", "scheduled", "out-of-cycle", "immediate")
OUTCOME_WORDS = {"defer": "Defer", "scheduled": "Plan update", "out-of-cycle": "Update soon", "immediate": "Act now"}

CRITICALITY_TO_IMPACT = {"low": "low", "medium": "medium", "high": "high", "critical": "very high"}
NOT_AUTOMATABLE_HINTS = (  # most specific first: the first hit is quoted in the question to a person
    "authenticated attacker", "authenticated user", "user interaction", "physical access", "local attacker",
    "local user", "valid credentials", "crafted file", "malicious file", "an authenticated", "locally",
    "convince", "tricking", "opening a", "open a",
)


@dataclass(frozen=True)
class Step:
    point: DecisionPoint
    value: str
    reason: str
    fact: bool  # True: taken from a source or the inventory. False: PatchOwner's own estimate.
    question: str | None = None  # something a person should confirm; an estimate never lowers urgency on its own


@dataclass(frozen=True)
class Assessment:
    steps: tuple[Step, ...]  # in POINTS order

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(s.value for s in self.steps)

    @property
    def leaf_key(self) -> str:
        return "|".join(self.values)

    def with_value(self, point: DecisionPoint, value: str) -> "Assessment":
        return Assessment(tuple(s if s.point is not point else Step(point, value, "confirmed by a person", True) for s in self.steps))

    @property
    def questions(self) -> list[str]:
        return [s.question for s in self.steps if s.question]

    def because(self) -> str:
        """The three clauses a person needs. Exploitation is omitted: for KEV it is always 'right now'."""
        clauses = [s.point.clause[s.value] for s in self.steps if s.point is not EXPLOITATION]
        return ", ".join(clauses[:-1]) + ", and " + clauses[-1]

    def vector(self, when: int | None = None) -> str:
        pairs = sorted(f"{s.point.key}:{s.point.abbrev[s.value]}" for s in self.steps)
        tail = f"/{when}" if when else ""
        return "SSVCv2/" + "/".join(pairs) + tail + "/"


@dataclass(frozen=True)
class Outcome:
    priority: str
    row: int


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    name: str
    rows: dict[tuple[str, ...], tuple[str, int]]  # decision values -> (outcome, row number)
    header: list[str]

    @classmethod
    def load(cls, path: Path | str, name: str | None = None) -> "Policy":
        path = Path(path)
        return cls.parse(path.read_text(), name or path.stem)

    @classmethod
    def parse(cls, text: str, name: str) -> "Policy":
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        if not header or len(header) != 2 + len(POINTS):
            raise PolicyError(f"Expected columns: row, {', '.join(p.name for p in POINTS)}, outcome.")
        rows: dict[tuple[str, ...], tuple[str, int]] = {}
        for line_no, line in enumerate(reader, start=2):
            if not line or not any(c.strip() for c in line):
                continue
            row_num = int(line[0])
            values = tuple(c.strip().lower() for c in line[1:1 + len(POINTS)])
            outcome = line[1 + len(POINTS)].strip().lower()
            for p, v in zip(POINTS, values):
                if v not in p.values:
                    raise PolicyError(f"Line {line_no}: '{v}' is not a valid {p.name} value ({', '.join(p.values)}).")
            if outcome not in OUTCOMES:
                raise PolicyError(f"Line {line_no}: '{outcome}' is not a valid outcome ({', '.join(OUTCOMES)}).")
            rows[values] = (outcome, row_num)
        expected = 1
        for p in POINTS:
            expected *= len(p.values)
        if len(rows) != expected:
            raise PolicyError(f"Policy has {len(rows)} rows; the deployer tree needs all {expected} combinations.")
        return cls(name=name, rows=rows, header=header)

    @classmethod
    def default(cls) -> "Policy":
        return cls.load(DEFAULT_POLICY, "SEI deployer tree (default)")

    def evaluate(self, a: Assessment) -> Outcome:
        outcome, row = self.rows[a.values]
        return Outcome(outcome, row)

    def outcome_for(self, values: tuple[str, ...]) -> tuple[str, int]:
        return self.rows[values]

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(self.header)
        for values, (outcome, row) in sorted(self.rows.items(), key=lambda kv: kv[1][1]):
            w.writerow([row, *values, outcome])
        return buf.getvalue()


def automatable_hint(description: str) -> str:
    """A phrase in the advisory text suggesting the attack needs a person, or '' if none."""
    d = description.lower()
    for h in NOT_AUTOMATABLE_HINTS:
        # Whole words only: "unauthenticated attacker" must not trigger "authenticated attacker".
        if re.search(r"\b" + re.escape(h) + r"\b", d):
            return h
    return ""


def assess(adv: Advisory, asset: Asset) -> Assessment:
    """Map one advisory and one inventory row onto the four deployer decision points, with reasons."""
    steps: list[Step] = [Step(EXPLOITATION, "active", f"CISA lists {adv.cve_id} as exploited in the wild", True)]

    if asset.exposure:
        steps.append(Step(EXPOSURE, asset.exposure, "exposure set explicitly in the inventory", True))
    elif asset.internet_exposed:
        steps.append(Step(EXPOSURE, "open", "the inventory marks this asset internet-facing", True))
    else:
        steps.append(Step(EXPOSURE, "controlled", "not internet-facing; assumed reachable from the internal network", False))

    hint = automatable_hint(adv.description)
    steps.append(Step(
        AUTOMATABLE, "yes",
        "assumed the attack can run by itself, the worst case, until a person says otherwise", False,
        question=f"CISA's text mentions “{hint}”. Does this attack need a person's help?" if hint else None,
    ))

    if asset.human_impact:
        steps.append(Step(HUMAN_IMPACT, asset.human_impact, "human impact set explicitly in the inventory", True))
    elif not asset.is_production:
        steps.append(Step(HUMAN_IMPACT, "low", f"this is a {asset.environment} system; mission impact is at most degraded", False))
    else:
        impact = CRITICALITY_TO_IMPACT.get(asset.criticality, "medium")
        steps.append(Step(HUMAN_IMPACT, impact, f"criticality '{asset.criticality}' in the inventory", False))
    return Assessment(tuple(steps))


def plain_policy(policy: Policy) -> list[str]:
    """The active-exploitation subtree as a few sentences, leaves with the same answer collapsed."""
    impacts = HUMAN_IMPACT.values

    def runs(values_prefix: tuple[str, ...]) -> list[tuple[str, list[str]]]:
        out: list[tuple[str, list[str]]] = []
        for hi in impacts:
            o = policy.outcome_for((*values_prefix, hi))[0]
            if out and out[-1][0] == o:
                out[-1][1].append(hi)
            else:
                out.append((o, [hi]))
        return out

    def phrase(r: list[tuple[str, list[str]]]) -> str:
        if len(r) == 1:
            return OUTCOME_WORDS[r[0][0]] + "."
        main = max(r, key=lambda x: len(x[1]))
        parts = [OUTCOME_WORDS[main[0]]]
        for o, his in r:
            if o == main[0]:
                continue
            if his[-1] == impacts[-1]:
                cond = f"if it would hurt {HUMAN_IMPACT.word(his[0])} or more" if len(his) < len(impacts) else ""
                if his[0] == "very high":
                    cond = "if it could stop the business"
            elif his[0] == impacts[0]:
                cond = f"if it would only hurt {HUMAN_IMPACT.word(his[-1])}"
            else:
                cond = "if it would hurt " + " or ".join(HUMAN_IMPACT.word(h) for h in his)
            parts.append(f"{OUTCOME_WORDS[o]} {cond}")
        return "; ".join(parts) + "."

    lead = {"open": "Reachable from the internet", "controlled": "Reachable from inside only", "small": "Isolated"}
    lines: list[str] = []
    for ex in reversed(EXPOSURE.values):  # internet first
        by_auto = {au: runs(("active", ex, au)) for au in AUTOMATABLE.values}
        if by_auto["yes"] == by_auto["no"]:
            lines.append(f"{lead[ex]}: {phrase(by_auto['yes'])}")
        else:
            lines.append(f"{lead[ex]} and the attack can run by itself: {phrase(by_auto['yes'])}")
            lines.append(f"{lead[ex]} but the attack needs a person: {phrase(by_auto['no'])}")
    return lines
