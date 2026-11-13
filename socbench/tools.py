"""The simulated SOC tools an agent can call. Each call returns plain JSON."""
from __future__ import annotations

from typing import Any

TOOL_HELP = {
    "get_asset": {"args": ["host"], "doc": "Inventory record for a host."},
    "get_user": {"args": ["user"], "doc": "Directory record for a user."},
    "search_logs": {"args": ["query"], "doc": "Case-insensitive substring over host, user and text. Max 10 rows."},
    "threat_intel": {"args": ["ioc"], "doc": "Reputation for a domain or IP."},
    "related_alerts": {"args": ["entity"], "doc": "Other alerts for a host or a user."},
}
MAX_ROWS = 10


class World:
    def __init__(self, world: dict[str, Any]):
        self.w = world
        self.retrieved: set[str] = set()

    def call(self, tool: str, args: Any) -> dict[str, Any]:
        if tool not in TOOL_HELP:
            return {"error": f"unknown tool {tool!r}", "tools": sorted(TOOL_HELP)}
        if not isinstance(args, dict):
            return {"error": "args must be an object"}
        need = TOOL_HELP[tool]["args"][0]
        val = args.get(need)
        if not isinstance(val, str) or not val.strip() or len(val) > 200:
            return {"error": f"'{need}' must be a non-empty string up to 200 chars"}
        val = val.strip()
        return getattr(self, "_" + tool)(val)

    def _get_asset(self, host: str) -> dict[str, Any]:
        a = self.w["assets"].get(host)
        return {"host": host, **a} if a else {"error": "not found", "host": host}

    def _get_user(self, user: str) -> dict[str, Any]:
        u = self.w["users"].get(user)
        return {"user": user, **u} if u else {"error": "not found", "user": user}

    def _search_logs(self, query: str) -> dict[str, Any]:
        q = query.lower()
        hits = [l for l in self.w["logs"] if q in l["text"].lower() or q == (l["host"] or "").lower() or q == (l["user"] or "").lower()]
        for l in hits[:MAX_ROWS]:
            self.retrieved.add(l["id"])
        return {"query": query, "total": len(hits), "rows": hits[:MAX_ROWS]}

    def _threat_intel(self, ioc: str) -> dict[str, Any]:
        r = self.w["intel"].get(ioc)
        return {"ioc": ioc, **r} if r else {"ioc": ioc, "verdict": "unknown", "detail": "No data."}

    def _related_alerts(self, entity: str) -> dict[str, Any]:
        return {"entity": entity, "alerts": self.w["related"].get(entity, [])}
