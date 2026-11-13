"""Command line: list, validate, run, report."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import report as rep
from . import runner
from . import scenario as sc
from . import scoring


def _load(args) -> list[dict]:
    scns = sc.load_dir(args.scenarios)
    if getattr(args, "only", None):
        keep = set(args.only)
        missing = keep - {s["id"] for s in scns}
        if missing:
            raise sc.ScenarioError(f"unknown scenario ids: {', '.join(sorted(missing))}")
        scns = [s for s in scns if s["id"] in keep]
    return scns


def cmd_list(args) -> int:
    for s in _load(args):
        inj = " [injection]" if s["truth"].get("injection") else ""
        print(f"{s['id']:30} {s['category']:18} {s['difficulty']:7} budget={s['budget_steps']}{inj}")
    return 0


def cmd_validate(args) -> int:
    try:
        n = len(sc.load_dir(args.scenarios))
    except sc.ScenarioError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    print(f"{n} scenarios valid")
    return 0


def cmd_run(args) -> int:
    scns = _load(args)
    rows = runner.run_all(args.agent, scns, args.timeout)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=1) + "\n")
    print(rep.markdown(rows))
    print(f"results written to {out}")
    return 0


def cmd_report(args) -> int:
    rows = json.loads(pathlib.Path(args.results).read_text())
    if args.md:
        pathlib.Path(args.md).write_text(rep.markdown(rows))
    if args.html:
        d = pathlib.Path(args.html).parent
        d.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.html).write_text(rep.html_report(rows))
        (d / "report.css").write_text(rep.CSS)
        (d / "report.js").write_text(rep.JS)
    if not (args.md or args.html):
        print(rep.markdown(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="socbench", description="Benchmark SOC triage agents.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, help_ in (("list", cmd_list, "list scenarios"), ("validate", cmd_validate, "validate a scenario set"), ("run", cmd_run, "run agents")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--scenarios", help="directory of scenario JSON files (default: bundled public set)")
        p.set_defaults(fn=fn)
        if name == "run":
            p.add_argument("--agent", action="append", required=True, help=f"builtin ({', '.join(runner.BUILTIN)}), path.py, or cmd:<command>; repeatable")
            p.add_argument("--only", nargs="+", help="scenario ids to run")
            p.add_argument("--timeout", type=float, default=30.0, help="seconds per scenario")
            p.add_argument("--out", default="results/run.json")
    r = sub.add_parser("report", help="render results")
    r.add_argument("results")
    r.add_argument("--md")
    r.add_argument("--html")
    r.set_defaults(fn=cmd_report)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (sc.ScenarioError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
