"""Mechanically trace public numbers to reports.

docs/claims.json lists claims: {"id", "text", "expr", "vars", "fmt"}. Each var points into a JSON report
({"file", "path"} and optionally "len" or "count_where": {"field", "equals"}). The expression is evaluated with only
abs/len/round available; formatting the result with `fmt` must reproduce `text` exactly. Documents tag each number
with [C:<id>]; a tag naming an unknown claim, or an untagged figure (digits followed by %, x, a time unit or a count word)
in a checked document, is a failure.

    python scripts/check_claims.py            exit 1 and list problems if anything is untraceable
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKED = ["docs/ANNOUNCEMENT.md", "docs/WHY_VEP.md", "docs/COMPARISON.md", "docs/FAQ.md", "docs/SECURITY_LIMITATIONS.md"]
TAG = re.compile(r"\[C:([A-Za-z0-9_\-]+)\]")
FIGURE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?\s?(?:%|x\b|×|ms\b|s\b|jobs|vectors|tests|workers)")


def _dig(doc, path):
    for p in path:
        doc = doc[p]
    return doc


def _value(spec: dict):
    doc = json.loads((ROOT / spec["file"]).read_text())
    v = _dig(doc, spec["path"])
    if spec.get("len"):
        return len(v)
    if "count_where" in spec:
        w = spec["count_where"]
        return sum(1 for x in v.values() if x.get(w["field"]) == w["equals"])
    return v


def evaluate(claim: dict) -> str:
    env = {k: _value(s) for k, s in claim["vars"].items()}
    return claim["fmt"].format(eval(claim["expr"], {"__builtins__": {}, "abs": abs, "len": len, "round": round}, env))


def verify() -> list[str]:
    problems = []
    claims = {c["id"]: c for c in json.loads((ROOT / "docs" / "claims.json").read_text())}
    for cid, c in claims.items():
        try:
            got = evaluate(c)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{cid}: cannot evaluate ({exc.__class__.__name__}: {exc})")
            continue
        if got != c["text"]:
            problems.append(f"{cid}: report says {got!r}, document claims {c['text']!r}")
    for doc in CHECKED:
        p = ROOT / doc
        if not p.exists():
            continue
        for n, line in enumerate(p.read_text().splitlines(), 1):
            tags = TAG.findall(line)
            for t in tags:
                if t not in claims:
                    problems.append(f"{doc}:{n}: unknown claim tag {t}")
                elif claims[t]["text"] not in line:
                    problems.append(f"{doc}:{n}: tag {t} but its figure {claims[t]['text']!r} is not on the line")
            if not line.lstrip().startswith(("|---", "```")) and FIGURE.search(line) and not tags:
                problems.append(f"{doc}:{n}: untraced figure: {FIGURE.search(line).group(0)!r}")
    return problems


if __name__ == "__main__":
    probs = verify()
    print("\n".join(probs) if probs else "claims: all traced and consistent")
    sys.exit(1 if probs else 0)
