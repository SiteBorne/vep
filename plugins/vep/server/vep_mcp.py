#!/usr/bin/env python3
"""Start the local VEP MCP server (stdio). Requires the `vep-protocol` package with the `mcp` extra to be installed already.

This launcher installs nothing and opens no network connection. The server runs with the authority passed on the command line
(read and register by default; it cannot evaluate code). The project root is the working directory Claude Code starts it in.
"""
import sys

try:
    from vep.mcp_server import main
except ImportError as exc:
    sys.stderr.write(
        "VEP is not installed for this Python (%s). Install it first, for example:\n"
        "  python3 -m pip install 'vep-protocol[mcp] @ git+https://github.com/SiteBorne/vep@protocol/claude-native-0.6'\n"
        "See the plugin README.\n" % exc)
    sys.exit(2)

sys.exit(main(sys.argv[1:]))
