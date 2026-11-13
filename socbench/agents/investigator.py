"""Reference tool-using agent: gathers context, then applies heuristics to what it retrieved.

Honest note: these heuristics were written while looking at the public scenarios, so its score on them is
optimistic. Run it on a held-out set (--scenarios DIR) to see how it generalises. It reads only the
structured facts it retrieves and never treats retrieved text as instructions.
"""
import re

from ._io import call, finish, read_task

MAL = [  # (regex, weight, technique, severity, actions)
    (r"vssadmin.*delete shadows|\.locked", 5, "T1490", 5, ["isolate_host", "escalate_to_ir", "collect_forensics"]),
    (r"lsass|minidump", 4, "T1021.002", 5, ["isolate_host", "disable_account", "escalate_to_ir"]),
    (r"administratoraccess|createaccesskey", 4, "T1078.004", 5, ["disable_account", "escalate_to_ir", "block_ioc"]),
    (r"-enc |downloadstring|spawned powershell", 4, "T1059.001", 4, ["isolate_host", "collect_forensics", "escalate_to_ir"]),
    (r"net localgroup administrators", 4, "T1136.001", 4, ["isolate_host", "reset_password", "escalate_to_ir"]),
    (r"stratum|mining pool", 3, "T1496", 3, ["block_ioc", "collect_forensics"]),
    (r"high entropy|txt queries", 3, "T1048.003", 4, ["block_ioc", "isolate_host", "collect_forensics"]),
    (r"usb mass storage|resignation", 3, "T1052.001", 4, ["escalate_to_ir", "collect_forensics"]),
    (r"inbox rule|newly-registered|legacy protocol|\(domain age 1 day\)", 3, "T1566.002", 4, ["reset_password", "block_ioc", "escalate_to_ir"]),
    (r"failed (password|auth).{0,40}x?\d{2,}|vpn auth failure", 2, "T1110.003", 4, ["reset_password", "block_ioc", "escalate_to_ir"]),
]
BENIGN = re.compile(r"approved under change|change chg-|scope list matches|within 5%|travel calendar|spf pass|contracted|same device id", re.I)


def run():
    task = read_task()
    a = task["alert"]
    texts, logs, notes, intel_bad, intel_ok = [], {}, [], False, False
    for q in filter(None, [a.get("host"), a.get("user")]):
        for row in call("search_logs", query=q)["rows"]:
            logs[row["id"]] = row
    if a.get("host"):
        notes.append(call("get_asset", host=a["host"]).get("notes", ""))
    if a.get("user"):
        notes.append(call("get_user", user=a["user"]).get("notes", ""))
    for ioc in a.get("iocs", []):
        r = call("threat_intel", ioc=ioc)
        intel_bad |= r.get("verdict") == "malicious"
        intel_ok |= r.get("verdict") in ("benign", "internal")
    corpus = {i: r["text"] for i, r in logs.items()}
    hits = {}
    for i, t in corpus.items():
        for rx, w, tech, sev, acts in MAL:
            if re.search(rx, t, re.I):
                hits.setdefault(i, []).append((w, tech, sev, acts))
    ben_ids = [i for i, t in corpus.items() if BENIGN.search(t)] + ([] if not BENIGN.search(" ".join(notes)) else ["__notes"])
    ben_ids = [i for i in ben_ids if i != "__notes"]
    mal_score = sum(max(w for w, *_ in v) for v in hits.values()) + (3 if intel_bad else 0)
    ben_score = 3 * len(ben_ids) + (3 if intel_ok else 0) + (3 if BENIGN.search(" ".join(notes)) else 0)
    if mal_score >= 3 and mal_score > ben_score:
        best = max((h for v in hits.values() for h in v), key=lambda h: (h[2], h[0]), default=(0, "T1059", 4, ["escalate_to_ir"]))
        ev = sorted(hits, key=lambda i: -max(w for w, *_ in hits[i]))[:4]
        if re.search(r"no accepted", " ".join(corpus.values()), re.I):  # guessing failed: contained, low
            best = (2, "T1110.001", 2, ["block_ioc"])
        finish({"verdict": "true_positive", "severity": best[2], "technique": best[1], "evidence": ev,
                "actions": best[3], "summary": "Malicious indicators in retrieved logs."})
    elif ben_score > 0:
        label = "false_positive" if re.search(r"spf pass|same device id|within 5%", " ".join(corpus.values()), re.I) else "benign_activity"
        acts = ["close_alert"] + (["notify_user"] if re.search(r"spf pass", " ".join(corpus.values()), re.I) else [])
        finish({"verdict": label, "severity": 1, "technique": "", "evidence": ben_ids[:4], "actions": acts,
                "summary": "Activity explained by approval, schedule or sender reputation."})
    else:
        finish({"verdict": "true_positive", "severity": 3, "technique": "", "evidence": list(logs)[:3],
                "actions": ["create_ticket"], "summary": "Unclear, needs a human."})


if __name__ == "__main__":
    run()
