# VEP plugin for Claude Code

VEP (Verified Evolution Protocol) lets an agent ask for a code change to be verified and lets someone else check the answer. This plugin adds a Skill that teaches Claude three workflows and a local MCP server entry that talks to the VEP reference implementation on your machine.

## What it does
* **Register and verify a change**: freeze the current tree and its tests, register a candidate, and (only if you enable it) run the protected evaluation.
* **Explain a failed invariant**: which rule failed, why, the remedy, and handles to the full logs.
* **Retrieve exact evidence**: certificate and evidence identities, and an exportable bundle a third party verifies under their own trust policy.

## Prerequisites
VEP is a Python package (Python 3.11 or newer). It is not on PyPI yet, so install it from the repository before enabling the plugin:

```bash
python3 -m pip install 'vep-protocol[mcp] @ git+https://github.com/SiteBorne/vep@protocol/claude-native-0.6'
```

## What the plugin runs, sends and changes
* It starts `python3 server/vep_mcp.py`, which imports the installed `vep` package and runs the MCP server over stdio. No network connection is opened, nothing is downloaded at start-up, and no credential is read or sent.
* The server is started with the `read,register` authority. It can inspect state, freeze a baseline and register candidates; it cannot run your code. Evaluating runs the candidate's tests unisolated on your machine and is deliberately not enabled here; the operator enables it separately by changing the server arguments (see the VEP documentation).
* The server writes its state under `.vep/` in the project directory. It does not edit your source files, `.claude/settings.json` or permissions, and the plugin contains no hooks.
* No tool accepts a verdict, an authority or a trust level from the model, so Claude cannot declare a change certified.

## Supported surfaces and limits
Local stdio MCP servers run in Claude Code on your computer; this plugin has not been tested on other surfaces. The server uses the project directory Claude Code starts it in as its root, which has not been confirmed in a live Claude Code session yet. This listing is not an external security audit, and VEP does not make running untrusted code safe.

License: Apache-2.0. Source and documentation: https://github.com/SiteBorne/vep
