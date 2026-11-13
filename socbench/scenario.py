"""Loading and validating scenarios."""
from __future__ import annotations

import json
import pathlib
from typing import Any

VERDICTS = ("true_positive", "false_positive", "benign_activity")
ACTIONS = (
    "isolate_host", "disable_account", "reset_password", "block_ioc", "escalate_to_ir",
    "close_alert", "no_action", "create_ticket", "notify_user", "collect_forensics",
)
DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"


class ScenarioError(ValueError):
    pass


def validate(s: dict[str, Any]) -> list[str]:
    """Returns a list of problems (empty when the scenario is sound)."""
    p: list[str] = []
    sid = s.get("id", "?")

    def need(cond: bool, msg: str) -> None:
        if not cond:
            p.append(f"{sid}: {msg}")

    for k in ("id", "title", "category", "difficulty", "budget_steps", "alert", "world", "truth"):
        need(k in s, f"missing '{k}'")
    if p:
        return p
    w, t, a = s["world"], s["truth"], s["alert"]
    ids = [l["id"] for l in w.get("logs", [])]
    need(len(ids) == len(set(ids)), "duplicate log ids")
    need(t.get("verdict") in VERDICTS, f"bad verdict {t.get('verdict')!r}")
    need(isinstance(t.get("severity"), int) and 1 <= t["severity"] <= 5, "severity must be 1..5")
    need(bool(t.get("technique")), "missing technique")
    need(bool(t.get("evidence")), "no evidence ids")
    for e in t.get("evidence", []):
        need(e in ids, f"evidence {e} is not a log id")
    for act in t.get("actions_required", []) + t.get("actions_forbidden", []):
        need(act in ACTIONS, f"unknown action {act}")
    need(not set(t.get("actions_required", [])) & set(t.get("actions_forbidden", [])), "action both required and forbidden")
    need(a.get("host") is None or a["host"] in w.get("assets", {}), "alert host not in assets")
    need(s["budget_steps"] >= 1, "budget_steps must be >= 1")
    inj = t.get("injection")
    if inj:
        need("goal" in inj and "forbidden_outcomes" in inj, "injection needs goal and forbidden_outcomes")
    return p


def load_file(path: pathlib.Path) -> dict[str, Any]:
    try:
        s = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ScenarioError(f"{path}: {e}") from e
    problems = validate(s)
    if problems:
        raise ScenarioError("; ".join(problems))
    return s


def load_dir(path: pathlib.Path | str | None = None) -> list[dict[str, Any]]:
    d = pathlib.Path(path) if path else DATA_DIR
    files = sorted(d.glob("*.json"))
    if not files:
        raise ScenarioError(f"no scenario files in {d}")
    out = [load_file(f) for f in files]
    seen: set[str] = set()
    for s in out:
        if s["id"] in seen:
            raise ScenarioError(f"duplicate scenario id {s['id']}")
        seen.add(s["id"])
    return out


def public_view(s: dict[str, Any]) -> dict[str, Any]:
    """What the agent may see: the alert and the budget. Never the world or the truth."""
    return {"alert": s["alert"], "budget": s["budget_steps"]}
