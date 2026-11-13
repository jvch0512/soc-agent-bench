"""Runs an agent against scenarios. Agents are subprocesses speaking JSON lines on stdio."""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from . import scenario as sc
from . import scoring
from .tools import TOOL_HELP, World

MAX_STEPS = 25
MAX_LINE = 100_000
BUILTIN = ("naive", "rules", "investigator", "gullible")


def resolve(spec: str) -> list[str]:
    """Agent spec -> argv. A builtin name, a path to a .py file, or 'cmd:<shell words>'."""
    if spec in BUILTIN:
        return [sys.executable, "-m", f"socbench.agents.{spec}"]
    if spec.startswith("cmd:"):
        import shlex
        return shlex.split(spec[4:])
    if spec.endswith(".py"):
        return [sys.executable, spec]
    raise ValueError(f"unknown agent {spec!r}: use a builtin ({', '.join(BUILTIN)}), a .py path or 'cmd:...'")


class Session:
    """Protocol state for one scenario, independent of how the agent is connected."""

    def __init__(self, scn: dict[str, Any]):
        self.scn = scn
        self.world = World(scn["world"])
        self.steps = 0
        self.trace: list[dict[str, Any]] = []

    def task(self) -> dict[str, Any]:
        return {"type": "task", **sc.public_view(self.scn), "tools": TOOL_HELP}

    def tool(self, tool: Any, args: Any) -> dict[str, Any]:
        self.steps += 1
        obs = self.world.call(str(tool), args)
        self.trace.append({"tool": tool, "args": args, "ok": "error" not in obs})
        return {"type": "observation", "tool": tool, "result": obs}


def _result(scn, agent, sess, final, error, secs):
    clean, why = scoring.clean_final(final) if final is not None else (None, error or "no final answer")
    err = error or (why if clean is None else None)
    s = scoring.score(scn, clean, sess.steps, sess.world.retrieved)
    return {
        "agent": agent, "scenario": scn["id"], "category": scn["category"], "difficulty": scn["difficulty"],
        "is_injection": bool(scn["truth"].get("injection")), "score": s["total"], "parts": s["parts"],
        "hard_fail": s["hard_fail"], "injection_followed": s["injection_followed"],
        "steps": sess.steps, "budget": scn["budget_steps"], "error": err, "seconds": round(secs, 2),
        "final": clean, "trace": sess.trace,
    }


def run_callable(fn: Callable[[dict[str, Any], Callable[[str, dict], dict]], Any], scn: dict[str, Any], name: str = "callable") -> dict[str, Any]:
    """In-process agent: fn(task, call) -> final dict. `call(tool, args)` returns the result object."""
    sess = Session(scn)
    t0 = time.time()
    final, error = None, None

    def call(tool: str, args: dict) -> dict:
        if sess.steps >= MAX_STEPS:
            raise RuntimeError("step limit exceeded")
        return sess.tool(tool, args)["result"]

    try:
        final = fn(sess.task(), call)
    except Exception as e:  # an agent crash is a scored failure, not a harness crash
        error = f"agent error: {e}"
    return _result(scn, name, sess, final, error, time.time() - t0)


def _reader(pipe, q: "queue.Queue[Any]") -> None:
    try:
        for line in iter(lambda: pipe.readline(MAX_LINE + 1), b""):
            q.put(line)
    finally:
        q.put(None)


def run_process(argv: list[str], scn: dict[str, Any], name: str, timeout: float = 30.0) -> dict[str, Any]:
    sess = Session(scn)
    t0 = time.time()
    final, error = None, None
    env = {k: v for k, v in os.environ.items() if not k.endswith(("_KEY", "_TOKEN", "_SECRET"))}
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    except OSError as e:
        return _result(scn, name, sess, None, f"cannot start agent: {e}", 0.0)
    q: "queue.Queue[Any]" = queue.Queue()
    threading.Thread(target=_reader, args=(p.stdout, q), daemon=True).start()

    def send(obj: dict[str, Any]) -> bool:
        try:
            p.stdin.write((json.dumps(obj) + "\n").encode())
            p.stdin.flush()
            return True
        except (BrokenPipeError, OSError):
            return False

    try:
        send(sess.task())
        while True:
            left = timeout - (time.time() - t0)
            if left <= 0:
                error = f"timeout after {timeout:g}s"
                break
            try:
                line = q.get(timeout=left)
            except queue.Empty:
                error = f"timeout after {timeout:g}s"
                break
            if line is None:
                error = "agent exited without a final answer"
                break
            if len(line) > MAX_LINE:
                error = "message too large"
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                error = "agent sent invalid JSON"
                break
            if not isinstance(msg, dict):
                error = "agent message must be an object"
                break
            if "final" in msg:
                final = msg["final"]
                break
            if "tool" in msg:
                if sess.steps >= MAX_STEPS:
                    error = f"more than {MAX_STEPS} tool calls"
                    break
                if not send(sess.tool(msg["tool"], msg.get("args", {}))):
                    error = "agent closed its input"
                    break
            else:
                error = "message needs 'tool' or 'final'"
                break
    finally:
        try:
            p.kill()
        except OSError:
            pass
        p.wait()
        for f in (p.stdin, p.stdout):
            try:
                f.close()
            except OSError:
                pass
    return _result(scn, name, sess, final, error, time.time() - t0)


def run_all(agents: list[str], scenarios: list[dict[str, Any]], timeout: float = 30.0) -> list[dict[str, Any]]:
    rows = []
    for a in agents:
        argv = resolve(a)
        label = a if a in BUILTIN else os.path.basename(a.removeprefix("cmd:"))[:40]
        for s in scenarios:
            rows.append(run_process(argv, s, label, timeout))
    return rows
