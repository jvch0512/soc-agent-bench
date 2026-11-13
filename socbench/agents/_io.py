"""Tiny stdio helper shared by the reference agents. A third-party agent needs only this protocol."""
import json
import sys


def read_task():
    return json.loads(sys.stdin.readline())


def call(tool, **args):
    sys.stdout.write(json.dumps({"tool": tool, "args": args}) + "\n")
    sys.stdout.flush()
    return json.loads(sys.stdin.readline())["result"]


def finish(final):
    sys.stdout.write(json.dumps({"final": final}) + "\n")
    sys.stdout.flush()
