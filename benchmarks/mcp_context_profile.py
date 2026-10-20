"""Context/latency profile of the VEP MCP server over real stdio: tool-definition size, response sizes, call latency (no model, no network).

    python benchmarks/mcp_context_profile.py --out benchmarks/results/mcp-context-profile.json

Token figures are bytes/4 ESTIMATES (the same approximation vep.context uses); no provider usage is measured here, so no prompt-cache or
billing claim follows from this file.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from mcp.client.client import Client  # noqa: E402

from tests.test_mcp_server import params, project  # noqa: E402


async def main_async(out: str) -> dict:
    root = project()
    try:
        async with Client(params(root, "read,register")) as c:
            tools = (await c.list_tools()).tools
            defs = [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools]
            listing = json.dumps(defs, sort_keys=True, separators=(",", ":"))
            per_tool = {t["name"]: len(json.dumps(t, sort_keys=True, separators=(",", ":"))) for t in defs}
            lat = []
            for _ in range(60):
                t0 = time.perf_counter(); r = await c.call_tool("vep_status", {}); lat.append((time.perf_counter() - t0) * 1000)
            o = (await c.call_tool("vep_objective_create", {"title": "t"})).structured_content
            cand = (await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"]})).structured_content
            sizes = {"vep_status": len(json.dumps(r.structured_content)), "vep_objective_create": len(json.dumps(o)), "vep_candidate_register": len(json.dumps(cand)),
                     "vep_candidate_state": len(json.dumps((await c.call_tool("vep_candidate_state", {"candidate_id": cand["candidate_id"]})).structured_content))}
        doc = {"tools": len(defs), "tools_list_bytes": len(listing), "tools_list_tokens_estimate": len(listing) // 4,
               "per_tool_definition_bytes": per_tool, "response_bytes": sizes,
               "vep_status_latency_ms": {"median": round(statistics.median(lat), 2), "p95": round(sorted(lat)[int(len(lat) * .95) - 1], 2), "n": len(lat)},
               "note": "token numbers are bytes/4 estimates, not provider usage"}
    finally:
        shutil.rmtree(root.parent, True)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return doc


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True)
    print(json.dumps(asyncio.run(main_async(ap.parse_args().out)), indent=1))
