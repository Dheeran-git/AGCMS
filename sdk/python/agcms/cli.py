"""``agcms`` command-line entrypoint.

Subcommands:
    agcms verify <bundle.zip|dir>   — validate an exported audit bundle offline
    agcms version                   — print the SDK version

The verifier delegates to the bundled ``agcms.verifier`` module which is a
copy of the script shipped inside every audit-bundle ZIP — keeping the SDK
behavior bit-for-bit identical to the auditor's standalone tool.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence


def _cmd_verify(argv: Sequence[str]) -> int:
    if not argv:
        print("usage: agcms verify <bundle.zip|directory>", file=sys.stderr)
        return 2

    from agcms import verifier

    return verifier.main(list(argv))


def _cmd_version(_: Sequence[str]) -> int:
    from agcms import __version__

    print(__version__)
    return 0


_COMMANDS = {
    "verify": _cmd_verify,
    "version": _cmd_version,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in {"-h", "--help"}:
        print("usage: agcms <command> [options]")
        print("commands:")
        for name in _COMMANDS:
            print(f"  {name}")
        return 0 if args else 2

    cmd = args[0]
    handler = _COMMANDS.get(cmd)
    if handler is None:
        print(f"agcms: unknown command {cmd!r}", file=sys.stderr)
        return 2
    return handler(args[1:])


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
