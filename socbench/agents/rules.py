"""Baseline: keyword rules over the alert text only. Uses no tools, so it can cite no evidence."""
import re

from ._io import finish, read_task

task = read_task()
a = task["alert"]
text = (a["rule"] + " " + a["description"]).lower()
sev = {"low": 2, "medium": 3, "high": 4, "critical": 5}.get(a["severity_hint"], 3)
benign = re.search(r"scann|scan-|backup|reported by the recipient|impossible travel", text)
actions = ["close_alert"] if benign else ["escalate_to_ir"]
verdict = "false_positive" if benign else "true_positive"
finish({"verdict": verdict, "severity": 1 if benign else sev, "technique": "", "evidence": [], "actions": actions, "summary": "Keyword triage of the alert text."})
