#!/usr/bin/env python3
"""
Sentinel-DPDP patch verification gate (Level 3 skill script).

Accepts a patched tree only if:
  (a) at least one baseline finding is resolved,
  (b) no NEW findings are introduced,
  (c) every Python file in the tree still compiles.

Usage:
  python verify_patch.py <patched_dir> --baseline scan.json [--expect RULE_ID ...]
Exit 0 = verified, 1 = rejected.
"""
from __future__ import annotations

import argparse
import json
import py_compile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_pii_ast import Finding, scan  # noqa: E402


def _key(d: dict) -> str:
    return Finding(**{k: d[k] for k in ("rule_id", "file", "line", "sink_type", "pii_entity", "snippet")}).key()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--expect", nargs="*", default=[], help="rule IDs that must be fully resolved")
    a = ap.parse_args(argv)

    target = Path(a.target).resolve()
    base = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
    after = scan(target)

    b_keys = {_key(f): f for f in base["findings"]}
    a_keys = {_key(f): f for f in after["findings"]}
    resolved = [b_keys[k] for k in b_keys.keys() - a_keys.keys()]
    introduced = [a_keys[k] for k in a_keys.keys() - b_keys.keys()]
    unresolved_expected = [f for f in after["findings"] if f["rule_id"] in a.expect]

    compile_errors = []
    for py in target.rglob("*.py"):
        if any(p in py.parts for p in (".venv", "node_modules", "__pycache__")):
            continue
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as e:
            compile_errors.append(f"{py.relative_to(target)}: {e.msg.splitlines()[-1]}")

    checks = {
        "findings_resolved": len(resolved) > 0,
        "no_new_findings": not introduced,
        "expected_rules_cleared": not unresolved_expected,
        "python_compiles": not compile_errors,
    }
    verified = all(checks.values())
    result = {
        "verified": verified,
        "checks": checks,
        "risk_before": base["summary"]["risk_score"],
        "risk_after": after["summary"]["risk_score"],
        "resolved": [f"{f['file']}:{f['line']} {f['rule_id']}" for f in resolved],
        "introduced": [f"{f['file']}:{f['line']} {f['rule_id']}" for f in introduced],
        "compile_errors": compile_errors,
    }
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if verified else 1


if __name__ == "__main__":
    sys.exit(main())
