"""``mcp-inspector`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .core import SEVERITIES, audit_server, load_tools

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-inspector",
        description="Audit MCP tool definitions for injection, ambiguity, and destructive scope.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    check = parser.add_subparsers(dest="command", required=True).add_parser(
        "check", help="audit a tools.json payload")
    check.add_argument("file", help="JSON: {'tools': [...]}, {'result': {'tools': [...]}}, or a list")
    check.add_argument("--fail-on", choices=SEVERITIES, default="high")
    check.add_argument("--allow", action="append", default=[],
                       help="tool name whose destructive-verb finding is accepted")
    check.add_argument("--json", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        tools = load_tools(args.file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("cannot read %s: %s" % (args.file, exc), file=sys.stderr)
        return 2

    report = audit_server(tools)
    allowed = {name.strip().lower() for name in args.allow}
    findings = [finding for finding in report.findings
                if not (finding.code == "destructive-verb"
                        and finding.pointer.strip().lower() in allowed)]
    report.findings = findings

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print("%d tool(s), %d finding(s), worst: %s"
              % (report.tools, len(findings), report.worst))
        for finding in sorted(findings, key=lambda f: (-SEVERITIES.index(f.severity),
                                                       f.pointer, f.code)):
            print("  [%-6s] %-22s %-20s %s"
                  % (finding.severity, finding.code, finding.pointer, finding.message))

    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in findings) else 0
