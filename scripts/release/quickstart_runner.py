"""Execute every ```bash quickstart block of docs/QUICKSTART.md in a fresh temp dir.

    python scripts/release/quickstart_runner.py --bin-dir /path/to/venv/bin

The blocks run in order inside one shared scratch directory with `--bin-dir` first on PATH, so the
commands exercise the INSTALLED `vep`. Exit status 0 only if every block exits 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def blocks(text: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"```bash quickstart\n(.*?)```", text, re.S)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", required=True)
    ap.add_argument("--doc", default=str(ROOT / "docs" / "QUICKSTART.md"))
    a = ap.parse_args()
    bl = blocks(Path(a.doc).read_text())
    if not bl:
        print(json.dumps({"status": "FAIL", "reason": "no quickstart blocks"}))
        return 1
    work = Path(tempfile.mkdtemp(prefix="vep-quickstart-"))
    env = {"PATH": f"{a.bin_dir}:/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8"}
    results = []
    try:
        (work / "w").mkdir()
        for i, b in enumerate(bl, 1):
            r = subprocess.run(["/bin/bash", "-eu", "-o", "pipefail", "-c", b], cwd=work / "w", env=env,
                               capture_output=True, text=True, timeout=600)
            results.append({"block": i, "returncode": r.returncode})
            if r.returncode != 0:
                print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
                break
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ok = len(results) == len(bl) and all(x["returncode"] == 0 for x in results)
    print(json.dumps({"status": "PASS" if ok else "FAIL", "blocks": len(bl), "results": results}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
