# Retrieve exact evidence

1. `vep_candidate_state(candidate_id)` gives the evidence id and certificate id. Resources are also readable: `vep://evidence/{id}`, `vep://certificate/{id}/verification`, `vep://history/{candidate_id}`.
2. To hand evidence to someone else, `vep_export_evidence(certificate_id)` (needs `export`). It writes a v2 bundle under `.vep/exports` and returns path, size and sha256. Quote the sha256 so the recipient can check the file.
3. The recipient verifies with their own trust policy: `vep conformance verify --bundle FILE --trust-policy POLICY --now TIME`. A v2 bundle without a policy is refused on purpose; do not suggest `--internal-only` as proof of authorization.
4. Never paste whole logs; quote the handle and the relevant lines.
