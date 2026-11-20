#!/usr/bin/env python3
"""
Sentinel-DPDP deterministic PII sink scanner (Level 3 skill script).

Finds personal-data leaks with exact file:line evidence BEFORE any LLM is involved:
  * Python  : AST walk + intra-function taint tracking (PII-named sources -> log / LLM sinks)
  * JS / TS : line-level pattern matching for console/logger + LLM SDK calls + consent UI
  * SQL     : CREATE TABLE with PII columns but no retention / erasure column
  * Any file: hard-coded Aadhaar (Verhoeff-validated), PAN, Indian mobile, UPI IDs
Optionally merges Semgrep / Gitleaks results when those binaries are on PATH.

Stdlib only. Usage:
  python scan_pii_ast.py <target> [--format json|text|sarif] [--out FILE]
Exit code 1 if any critical/high finding exists (CI gate), else 0.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES_PATH = HERE.parent / "references" / "dpdp_2026_rules.json"

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".agent"}
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SQL_EXT = {".sql"}
TEXT_EXT = PY_EXT | JS_EXT | SQL_EXT | {".env", ".json", ".yaml", ".yml", ".toml", ".txt", ".md", ".html"}

# ---------------------------------------------------------------- PII vocabulary
PII_NAME_PATTERNS: dict[str, re.Pattern] = {
    "aadhaar": re.compile(r"aadh?aa?r|uidai|\buid\b", re.I),
    "pan": re.compile(r"(^|_|\b)pan(_?(no|num|number|card))?($|_|\b)", re.I),
    "phone": re.compile(r"phone|mobile|msisdn|contact_?no", re.I),
    "email": re.compile(r"e_?mail", re.I),
    "upi": re.compile(r"\bupi|vpa\b", re.I),
    "card": re.compile(r"card_?(no|num|number)|\bcvv\b|\bpan_?card\b", re.I),
    "dob": re.compile(r"\bdob\b|date_?of_?birth|birth_?date", re.I),
    "health": re.compile(r"diagnos|medical|health_?record|prescription", re.I),
    "address": re.compile(r"\baddress\b|home_addr", re.I),
}
MASK_FUNC_RE = re.compile(r"mask|redact|hash|anonymi[sz]e|tokeni[sz]e|encrypt", re.I)

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "print"}
LOGGER_NAMES = re.compile(r"^(log|logger|logging|_logger|LOG|console)$|logger$", re.I)
LLM_CALL_SUFFIXES = (
    "generate_content", "generate_content_async", "send_message",
    "chat.completions.create", "completions.create", "messages.create",
    "responses.create", "invoke", "ainvoke",
)
LLM_HOST_RE = re.compile(r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai", re.I)

# ---------------------------------------------------------------- literal detectors
_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]


def verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


AADHAAR_LIT = re.compile(r"(?<!\d)([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
PAN_LIT = re.compile(r"(?<![A-Z0-9])[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z](?![A-Z0-9])")
PHONE_LIT = re.compile(r"(?<!\d)(?:\+91[ -]?|0)?[6-9]\d{9}(?!\d)")
UPI_LIT = re.compile(r"\b[\w.\-]{2,}@(?:okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|upi|apl)\b", re.I)


# ---------------------------------------------------------------- data model
@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    sink_type: str
    pii_entity: str
    snippet: str
    severity: str = ""
    dpdp_section: str = ""
    title: str = ""
    detector: str = "sentinel-ast"
    evidence: dict = field(default_factory=dict)

    def key(self) -> str:
        """Line-independent identity used for baseline diffing."""
        compact = re.sub(r"\s+", "", self.snippet)
        return f"{self.rule_id}|{self.file}|{self.pii_entity}|{compact}"


def load_rules() -> dict[str, dict]:
    data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    return {r["rule_id"]: r for r in data["rules"]}


def pii_of_name(name: str) -> str | None:
    for entity, pat in PII_NAME_PATTERNS.items():
        if pat.search(name):
            return entity
    return None


# ---------------------------------------------------------------- Python AST analysis
def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


class _PyAnalyzer(ast.NodeVisitor):
    """Per-function taint: variables assigned from PII-named expressions become tainted."""

    def __init__(self, rel: str, lines: list[str]):
        self.rel, self.lines = rel, lines
        self.findings: list[Finding] = []
        self.scopes: list[dict[str, str]] = [{}]
        self.llm_urls: set[str] = set()

    # ---- helpers
    def _pii_in(self, node: ast.AST) -> str | None:
        """Return PII entity if expression references PII without passing through a mask fn."""
        if isinstance(node, ast.Call):
            fname = _dotted(node.func)
            if MASK_FUNC_RE.search(fname):
                return None
            for a in list(node.args) + [k.value for k in node.keywords]:
                if (e := self._pii_in(a)):
                    return e
            return self._pii_in(node.func) if isinstance(node.func, ast.Attribute) else None
        if isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    return scope[node.id]
            return pii_of_name(node.id)
        if isinstance(node, ast.Attribute):
            return pii_of_name(node.attr) or self._pii_in(node.value)
        if isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str) and (e := pii_of_name(sl.value)):
                return e
            return self._pii_in(node.value)
        if isinstance(node, ast.keyword):
            return self._pii_in(node.value)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr_context):
                continue
            if (e := self._pii_in(child)):
                return e
        return None

    def _add(self, rule_id: str, node: ast.AST, sink: str, entity: str, **ev):
        ln = getattr(node, "lineno", 0)
        snippet = self.lines[ln - 1].strip() if 0 < ln <= len(self.lines) else ""
        self.findings.append(Finding(rule_id, self.rel, ln, sink, entity, snippet[:200], evidence=ev))

    # ---- scopes
    def visit_FunctionDef(self, node):
        self.scopes.append({})
        for arg in node.args.args + node.args.kwonlyargs:
            if (e := pii_of_name(arg.arg)):
                self.scopes[-1][arg.arg] = e
        self.generic_visit(node)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        e = self._pii_in(node.value)
        url_const = (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                     and LLM_HOST_RE.search(node.value.value))
        for t in node.targets:
            if isinstance(t, ast.Name):
                if url_const:
                    self.llm_urls.add(t.id)
                if e:
                    self.scopes[-1][t.id] = e
                else:
                    self.scopes[-1].pop(t.id, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and isinstance(node.target, ast.Name) and (e := self._pii_in(node.value)):
            self.scopes[-1][node.target.id] = e
        self.generic_visit(node)

    # ---- sinks
    def visit_Call(self, node):
        fname = _dotted(node.func)
        tail = fname.rsplit(".", 1)
        method = tail[-1]
        owner = tail[0] if len(tail) == 2 else ""
        args = list(node.args) + list(node.keywords)

        is_log = (fname == "print") or (method in LOG_METHODS and LOGGER_NAMES.search(owner.split(".")[-1] or ""))
        if is_log:
            for a in args:
                if (e := self._pii_in(a)):
                    self._add("DPDP-LOG-001", node, "log", e, call=fname)
                    break

        is_llm = any(fname.endswith(s) for s in LLM_CALL_SUFFIXES)
        if not is_llm and method in {"post", "request"}:
            is_llm = any((isinstance(a, ast.Constant) and isinstance(a.value, str) and LLM_HOST_RE.search(a.value))
                         or (isinstance(a, ast.Name) and a.id in self.llm_urls)
                         for a in ast.walk(node))
        if is_llm:
            for a in args:
                if (e := self._pii_in(a)):
                    self._add("DPDP-LLM-002", node, "llm_prompt", e, call=fname)
                    break
        self.generic_visit(node)


def scan_python(path: Path, rel: str) -> list[Finding]:
    src = path.read_text(encoding="utf-8", errors="ignore")
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError:
        return []
    an = _PyAnalyzer(rel, src.splitlines())
    an.visit(tree)
    return an.findings


# ---------------------------------------------------------------- JS / TS analysis
JS_LOG_RE = re.compile(r"\b(console|logger|log)\.(log|info|warn|error|debug)\s*\((.*)")
JS_LLM_RE = re.compile(r"(chat\.completions\.create|messages\.create|generateContent|responses\.create|sendMessage)\s*\(|fetch\(\s*['\"`]https://(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)")
JS_CONSENT_RE = re.compile(r"(defaultChecked(\s*=\s*\{?\s*true\s*\}?)?(?![\w=])|checked\s*=\s*\{\s*true\s*\}|\bchecked(?=[\s/>]))")
JS_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _js_pii(text: str) -> str | None:
    text_wo_mask = re.sub(r"\b\w*(mask|redact|hash)\w*\s*\([^)]*\)", "", text, flags=re.I)
    for ident in JS_IDENT_RE.findall(text_wo_mask):
        if (e := pii_of_name(ident)):
            return e
    return None


def scan_js(path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for i, line in enumerate(lines, 1):
        if (m := JS_LOG_RE.search(line)) and (e := _js_pii(m.group(3))):
            out.append(Finding("DPDP-LOG-001", rel, i, "log", e, line.strip()[:200]))
        if JS_LLM_RE.search(line):
            window = " ".join(lines[i - 1:i + 6])
            if (e := _js_pii(window)):
                out.append(Finding("DPDP-LLM-002", rel, i, "llm_prompt", e, line.strip()[:200]))
        if "<input" in line or "Checkbox" in line or "checkbox" in line:
            ctx = " ".join(lines[max(0, i - 3):i + 4]).lower()
            if JS_CONSENT_RE.search(line) and re.search(r"consent|marketing|share|agree|terms|promot", ctx):
                out.append(Finding("DPDP-CON-004", rel, i, "consent_ui", "any", line.strip()[:200]))
    return out


# ---------------------------------------------------------------- SQL analysis
CREATE_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\)\s*;", re.I | re.S)
RETENTION_RE = re.compile(r"retention|purge|expire|erase|ttl|delete_after", re.I)


def scan_sql(path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    src = path.read_text(encoding="utf-8", errors="ignore")
    for m in CREATE_RE.finditer(src):
        table, body = m.group(1), m.group(2)
        cols = [c.strip().split()[0].strip('`"') for c in body.split(",") if c.strip()]
        pii_cols = {c: e for c in cols if (e := pii_of_name(c))}
        if pii_cols and not RETENTION_RE.search(body):
            ln = src.count("\n", 0, m.start()) + 1
            entity = sorted(set(pii_cols.values()))
            out.append(Finding("DPDP-RET-003", rel, ln, "db_schema", ",".join(entity),
                               f"CREATE TABLE {table} (... {', '.join(pii_cols)} ...)",
                               evidence={"table": table, "pii_columns": list(pii_cols)}))
    return out


# ---------------------------------------------------------------- literal secrets / PII
def scan_literals(path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        for m in AADHAAR_LIT.finditer(line):
            digits = "".join(m.groups())
            if verhoeff_ok(digits):
                out.append(Finding("DPDP-SEC-006", rel, i, "source_literal", "aadhaar", line.strip()[:200],
                                   evidence={"verhoeff": True}))
        if PAN_LIT.search(line):
            out.append(Finding("DPDP-SEC-006", rel, i, "source_literal", "pan", line.strip()[:200]))
        if UPI_LIT.search(line):
            out.append(Finding("DPDP-SEC-006", rel, i, "source_literal", "upi", line.strip()[:200]))
        if PHONE_LIT.search(line) and re.search(r"['\"]", line):
            out.append(Finding("DPDP-SEC-006", rel, i, "source_literal", "phone", line.strip()[:200]))
    return out


# ---------------------------------------------------------------- optional external engines
def run_semgrep(target: Path) -> list[Finding]:
    if not shutil.which("semgrep"):
        return []
    try:
        res = subprocess.run(["semgrep", "--config", "p/secrets", "--json", "--quiet", str(target)],
                             capture_output=True, text=True, timeout=300)
        data = json.loads(res.stdout or "{}")
    except Exception:
        return []
    return [Finding("DPDP-SEC-006", os.path.relpath(r["path"], target).replace("\\", "/"), r["start"]["line"],
                    "source_literal", "secret", r.get("extra", {}).get("lines", "")[:200], detector="semgrep")
            for r in data.get("results", [])]


def run_gitleaks(target: Path) -> list[Finding]:
    if not shutil.which("gitleaks"):
        return []
    try:
        res = subprocess.run(["gitleaks", "detect", "--no-git", "-s", str(target), "-f", "json", "-r", "-"],
                             capture_output=True, text=True, timeout=300)
        data = json.loads(res.stdout or "[]")
    except Exception:
        return []
    return [Finding("DPDP-SEC-006", os.path.relpath(r["File"], target).replace("\\", "/"), r["StartLine"],
                    "source_literal", "secret", r.get("RuleID", ""), detector="gitleaks") for r in data]


# ---------------------------------------------------------------- driver
SEV_WEIGHT = {"critical": 25, "high": 15, "medium": 5, "low": 1}


def scan(target: Path) -> dict:
    rules = load_rules()
    findings: list[Finding] = []
    files = 0
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            p = Path(root) / n
            ext = p.suffix.lower() if p.suffix else p.name.lower()
            if ext not in TEXT_EXT or p.stat().st_size > 1_000_000:
                continue
            files += 1
            rel = p.relative_to(target).as_posix()
            if ext in PY_EXT:
                findings += scan_python(p, rel)
            if ext in JS_EXT:
                findings += scan_js(p, rel)
            if ext in SQL_EXT:
                findings += scan_sql(p, rel)
            findings += scan_literals(p, rel)
    findings += run_semgrep(target) + run_gitleaks(target)

    seen, unique = set(), []
    for f in findings:
        r = rules.get(f.rule_id, {})
        f.severity, f.dpdp_section, f.title = r.get("severity", "low"), r.get("dpdp_section", ""), r.get("title", "")
        k = (f.rule_id, f.file, f.line, f.pii_entity)
        if k not in seen:
            seen.add(k)
            unique.append(f)
    unique.sort(key=lambda f: (-SEV_WEIGHT.get(f.severity, 0), f.file, f.line))

    counts = {s: sum(1 for f in unique if f.severity == s) for s in SEV_WEIGHT}
    risk = min(100, sum(SEV_WEIGHT[f.severity] for f in unique))
    return {
        "tool": "sentinel-dpdp/scan_pii_ast",
        "rule_pack": "india-dpdp@2026.1",
        "target": str(target),
        "files_scanned": files,
        "engines": {"sentinel-ast": True, "semgrep": bool(shutil.which("semgrep")), "gitleaks": bool(shutil.which("gitleaks"))},
        "summary": {"risk_score": risk, "counts": counts, "total": len(unique),
                    "dpdp_sections": sorted({f.dpdp_section for f in unique})},
        "findings": [asdict(f) for f in unique],
    }


def to_sarif(report: dict) -> dict:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Sentinel-DPDP", "rules": [{"id": r} for r in sorted({f["rule_id"] for f in report["findings"]})]}},
            "results": [{
                "ruleId": f["rule_id"], "level": lvl[f["severity"]],
                "message": {"text": f"{f['title']} ({f['pii_entity']}) — DPDP {f['dpdp_section']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": f["line"]}}}],
            } for f in report["findings"]],
        }],
    }


def to_text(report: dict) -> str:
    s = report["summary"]
    out = [f"Sentinel-DPDP scan  files={report['files_scanned']}  risk={s['risk_score']}/100  {s['counts']}"]
    for f in report["findings"]:
        out.append(f"[{f['severity'].upper():8}] {f['file']}:{f['line']}  {f['rule_id']}  {f['pii_entity']:8} "
                   f"→ DPDP {f['dpdp_section']}\n           {f['snippet']}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--format", choices=["json", "text", "sarif"], default="text")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    report = scan(Path(a.target).resolve())
    payload = (json.dumps(report, indent=2, ensure_ascii=False) if a.format == "json"
               else json.dumps(to_sarif(report), indent=2) if a.format == "sarif" else to_text(report))
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(payload)
    return 1 if report["summary"]["counts"]["critical"] or report["summary"]["counts"]["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
