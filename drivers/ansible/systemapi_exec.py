"""Build a Starlark sys.exec.run program from an argv list.

The caller splits the command. This module does not invoke a shell.
An argument that contains a pipe, redirect, ``&&``, semicolon, or
backtick is refused.
"""

from __future__ import annotations

import json
import sys

_FORBIDDEN = ("|", ";", "&&", ">", "<", "`")
_MAX = 64 * 1024


def starlark_exec(argv: list[str]) -> str:
    if not isinstance(argv, list):
        raise ValueError("argv must be a list")
    if not argv:
        raise ValueError("empty argv")
    quoted: list[str] = []
    for arg in argv:
        if not isinstance(arg, str):
            raise ValueError("argv must be strings")
        for token in _FORBIDDEN:
            if token in arg:
                raise ValueError("refusing shell metacharacter")
        quoted.append(json.dumps(arg))
    args = ", ".join(quoted)
    return 'r = sys.exec.run(' + args + ')\nprint(r["output"])\n'


def main() -> None:
    raw = sys.stdin.read()
    if len(raw.encode("utf-8")) > _MAX:
        sys.stderr.write("input larger than 64 KiB\n")
        raise SystemExit(1)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        sys.stderr.write("expected a JSON list\n")
        raise SystemExit(1)
    if not isinstance(data, list):
        sys.stderr.write("expected a JSON list\n")
        raise SystemExit(1)
    try:
        sys.stdout.write(starlark_exec(data))
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
