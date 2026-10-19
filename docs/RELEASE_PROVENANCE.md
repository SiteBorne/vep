# Release Provenance and Artifact Verification

Four things are kept apart and never collapsed into a single "verified" badge:

| Concern | Question | Evidence in this project |
|---|---|---|
| **Source integrity** | Is this exactly the source that was reviewed/tagged? | git commit + tree hash recorded by the gate; tag `v0.4.0a1` must equal the gated commit |
| **Build provenance** | Which workflow/builder produced these bytes? | `release-provenance.json` (local record) and, **only when the GitHub release workflow runs**, a GitHub build attestation |
| **Test evidence** | What was run against them? | `release-gate.json` / `docs/RELEASE_GATE_REPORT.md`: per-gate PASS/FAIL/NOT_RUN/UNVERIFIED |
| **Evaluator trust** (VEP's own subject) | How trustworthy are *VEP certificates*? | `trust_level` inside signed evidence — unrelated to package signing |

**No SLSA level is claimed.** The local build record is explicitly *not* an in-toto or SLSA attestation. GitHub artifact attestations (the workflow uses `actions/attest-build-provenance`, SHA-pinned) follow the in-toto/SLSA provenance format when produced by the hosted release workflow, but meeting a specific SLSA level requires verifying every requirement of that level, which has not been done.

## Verify downloaded files
1. Checksums (works offline, proves only that the files match the manifest you also downloaded — so obtain the manifest from the release page, not from the same mirror as the files):
   ```bash
   sha256sum -c SHA256SUMS            # Linux
   shasum -a 256 -c SHA256SUMS        # macOS
   ```
2. Metadata sanity:
   ```bash
   python -m zipfile -l vep_protocol-0.4.0a1-py3-none-any.whl | grep -E "METADATA|entry_points|LICENSE"
   unzip -p vep_protocol-0.4.0a1-py3-none-any.whl 'vep_protocol-*/METADATA' | head -12
   ```
3. Build attestation (only if the release was produced by the GitHub workflow; requires the GitHub CLI and network):
   ```bash
   gh attestation verify vep_protocol-0.4.0a1-py3-none-any.whl --repo <OWNER>/<REPO>
   ```
   `<OWNER>/<REPO>` is intentionally not filled in: it must be the repository you obtained the release from. If the command reports no attestation, the build was not produced by the hosted workflow and **you have only the checksum guarantee**.
4. Install in a clean environment and run the shipped self-test:
   ```bash
   python3 -m venv /tmp/vep-check && /tmp/vep-check/bin/pip install vep_protocol-0.4.0a1-py3-none-any.whl
   /tmp/vep-check/bin/vep version --json
   ```

## Reproducing the gate
```bash
git checkout v0.4.0a1 && python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
scripts/release_check.sh          # writes release-gate.json and docs/RELEASE_GATE_REPORT.md
```
`release-provenance.json` lists the artifact hashes, source commit/tree, Python/platform used and the gate statuses known at that point. Wheels are built with setuptools from the tagged commit; byte-for-byte reproducibility across machines is **not** claimed or tested.

## Publication authority
* Build and verify jobs run with read-only tokens on the tagged commit only.
* Only the final `github-release` job has `contents: write`, `id-token: write`, `attestations: write`; only the `pypi` job (disabled unless a PyPI trusted publisher is configured and `PYPI_TRUSTED_PUBLISHING=true` is set) has `id-token: write` for OIDC. No long-lived PyPI token is used.
* Pull requests run `ci.yml` (read-only, no secrets). `pull_request_target` is forbidden by the release policy.
