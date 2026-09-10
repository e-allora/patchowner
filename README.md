# PatchSignal

Only verified, relevant, actionable vulnerability notices, routed to the person who can act.

This is the demo: upload a list of the technology you run, and PatchSignal replays the
CISA Known Exploited Vulnerabilities (KEV) catalog over the last 90 days and shows you
exactly which notices would have gone to whom, which stayed quiet, and why.

## Run it

```
uv sync
uv run patchsignal replay examples/inventory.csv        # writes out/report.html
uv run patchsignal serve                                # http://127.0.0.1:8000, upload a CSV
uv run pytest                                           # 77 tests, including the five routing scenarios from the doc
uv run patchsignal replay examples/inventory.csv --policy my_policy.csv   # your own risk appetite
```

The KEV feed is downloaded once to `data/kev.json`. Add `--refresh` to re-download.

## Inventory CSV

Required columns: `asset`, `vendor`, `product`.

Optional: `version`, `environment` (production/staging/test), `internet_exposed` (yes/no),
`criticality` (low/medium/high/critical), `owner_name`, `owner_email`, `team`, `accountable`, `oncall`, `escalate_to`,
`status` (active/retired), `exception_until` (YYYY-MM-DD), `exception_reason`,
and two SSVC overrides: `exposure` (small/controlled/open) and `human_impact` (low/medium/high/very high).
See `examples/inventory.csv`.

## How a notice is decided

The decision is an SSVC deployer tree: Stakeholder-Specific Vulnerability Categorization, from the
SEI/CERT at Carnegie Mellon (Spring et al., version 2.0, April 2021). Four fixed questions, in order,
then an answer that the organization owns.

| Decision point | Values | Where PatchSignal gets it |
|---|---|---|
| Exploitation | none, public poc, active | Always `active`: every KEV entry is exploited in the wild. Fact. |
| System Exposure | small, controlled, open | `exposure` column if set; else `internet_exposed` yes means open, otherwise controlled. |
| Automatable | no, yes | Always `yes`, the worst case. If the advisory text mentions authentication, user interaction, or local access, the notice carries a question for a person; only a person's confirmation moves it to `no`. An estimate never lowers urgency on its own. |
| Human Impact | low, medium, high, very high | `human_impact` column if set; else non-production is low, otherwise from `criticality`. |

The leaf is one of `defer`, `scheduled`, `out-of-cycle`, `immediate`, shown to people as
Defer, Plan update, Update soon, Act now. The default policy is the SEI example tree, unchanged
(`patchsignal/policies/deployer_default.csv`, 72 rows). The vocabulary is fixed so teams can compare;
the outcome on each row is the risk appetite and is meant to be edited.

Then PatchSignal adds what SSVC leaves out:

1. **Match** the advisory's vendor and product to each inventory row. Tiers: exact, likely, possible.
   KEV has no version data, so no notice ever claims a version is affected. A `possible` match gets no
   policy path; the owner is asked "does this apply?" instead.
2. **Route to three people, three ways.** The fixer (`owner_email`, or the fallback contact) gets the full
   notice; on Act now, `oncall` joins them. The accountable person (`accountable`) gets one status line
   per asset with no CVE numbers or descriptions. The escalation contact (`escalate_to`) hears nothing
   unless the window passes. Every answer carries its windows: Act now means acknowledge within 2 hours,
   plan within 8, escalate after 24; Update soon is 2 days, 7 days, 7 days; Plan update is 7, 30, 30.
   That table is the other half of the policy and sits under the tree.
3. **Suppress** with a visible reason when the asset is retired, has an exception on file, or the policy
   says defer. Every suppression appears under "Why was this not sent?"
4. **Budget.** If one person would receive more urgent notices than the budget, the report says so.
5. **Follow through.** Every notice has five working buttons: open the official fix, acknowledge, assign to
   someone else, this does not apply (with a reason), fixed. What people did is kept in a small JSON file
   (`out/state.json`, or `--state`), with full history under "For the auditor." Acknowledged is not
   remediated: only fixed and does-not-apply count as handled. "Does not apply" feeds back: the next replay
   suppresses that notice and shows the person's reason under "Why was this not sent?" The accountable
   person's status line changes with the state ("Dana has acknowledged it", "fixed, nothing needed from you").
   In `serve` mode the buttons write to the server; in the static report they fall back to the browser's own storage.

Every notice shows one plain sentence: "Act now, because it's reachable from the internet, the attack can
run by itself, and it would hurt a lot." The SSVC path, row, and vector string (for example
`SSVCv2/A:Y/E:A/H:H/Se:O/`) sit under "For the auditor." Facts and estimates are labeled separately.

## The policy page

The report's second tab opens with the whole policy in plain words, usually five or six sentences,
generated by collapsing tree leaves with the same answer:

> Reachable from the internet and the attack can run by itself: Update soon; Act now if it would hurt a lot or more.

Below it is the tree itself with the replay's counts on every branch, asked as three questions:
can attackers reach it, can the attack run by itself, how much would it hurt. Branches nothing landed
on are hidden. Click a leaf and the notices that landed there light up; click "Show me in the policy"
on a notice and its path lights up in the tree. Change an answer and every sentence, count, badge,
and card recomputes, and the edited policy CSV appears at the bottom, ready for `--policy`.
Nobody writes a rule. The SSVC vocabulary stays underneath for the auditor.

## What is deliberately not here yet

Jira and ServiceNow tickets, email and Slack delivery, overdue tracking against the acknowledge windows,
multi-tenant MSP views, KEV edit and retraction diffing, scanner integrations, and any AI-generated analysis.
Those wait for a paying pilot.

## Layout

```
patchsignal/kev.py        feed download, cache, date window
patchsignal/inventory.py  CSV parsing and validation
patchsignal/matching.py   vendor aliases, normalization, confidence tiers
patchsignal/ssvc.py       SSVC decision points, policy loading, assessment
patchsignal/decide.py     outcome to urgency, routing, escalation, suppression, budget
patchsignal/state.py      what people did about a notice, JSON file with history
patchsignal/report.py     HTML rendering (templates/report.html)
patchsignal/engine.py     one call that runs the replay
patchsignal/cli.py        `patchsignal replay` and `patchsignal serve`
patchsignal/web.py        upload form
```

## Credits

- Idea, doctrine, and product direction: e-all0ra. The PatchSignal doctrine, the funnel, the routing
  principle, and the five routing scenarios come from their design document.
- Implementation: built with Claude (Anthropic), Claude Fable 5.1, working in Claude Code, September 2026.
  Claude wrote the code, tests, and this README under e-all0ra's direction and review.
- Decision vocabulary: SSVC version 2.0, Software Engineering Institute, Carnegie Mellon University
  (Spring, Householder, Hatleback, Manion, Oliver, Sarvapalli, Tyzenhaus, Yarbrough, April 2021).
  Default policy table from the CERT/CC SSVC repository, unchanged.
- Exploited-vulnerability data: CISA Known Exploited Vulnerabilities catalog.
