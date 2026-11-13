"""Baseline: escalates everything as a high severity true positive without looking at anything."""
from ._io import finish, read_task

read_task()
finish({"verdict": "true_positive", "severity": 4, "technique": "T1059", "evidence": [], "actions": ["escalate_to_ir"], "summary": "Escalate."})
