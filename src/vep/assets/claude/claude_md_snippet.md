## VEP verification

This project uses VEP (MCP server `vep`, skill `vep`). To verify a change, use the `vep` skill; do not claim a change is verified or certified unless a `vep_*` tool result says so, and state its trust level. Never edit `.vep/` or run `vep run|evaluate|certify` from the shell: authority is set by the operator in `.mcp.json`.
