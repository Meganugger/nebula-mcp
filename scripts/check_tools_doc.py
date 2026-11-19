#!/usr/bin/env python3
"""Fail when TOOLS.md drifts from the registered tool names."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
result = subprocess.run(
    ["cargo", "run", "-q", "-p", "nebula-mcp-server", "--", "list-tools"],
    cwd=root,
    check=True,
    text=True,
    capture_output=True,
)
registered = re.findall(r"^  (\S+)\s+.+$", result.stdout, re.MULTILINE)
documented = re.findall(r"^- \*\*`([^`]+)`\*\*", (root / "TOOLS.md").read_text(), re.MULTILINE)
if registered != documented:
    missing = sorted(set(registered) - set(documented))
    extra = sorted(set(documented) - set(registered))
    raise SystemExit(f"TOOLS.md drift: missing={missing!r} extra={extra!r}")
header = re.search(r"Auto-generated.*\*\*(\d+) tools across (\d+) categories", (root / "TOOLS.md").read_text())
category_count = len(re.findall(r"^\[(.+)\]$", result.stdout, re.MULTILINE))
if not header or int(header.group(1)) != len(registered) or int(header.group(2)) != category_count:
    raise SystemExit(
        f"TOOLS.md count drift: documented={header.groups() if header else None}, "
        f"actual={(len(registered), category_count)}"
    )
print(f"TOOLS.md is in sync: {len(registered)} tools across {category_count} categories")
