"""Generate docs/VARIABLES.md from the code-level schemas plus the curated parameter list below.

Run:  python scripts/gen_variables.py          (writes docs/VARIABLES.md)
      python scripts/gen_variables.py --check  (exit 1 if the file is stale)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vep import objects, policies  # noqa: E402

I, P = "implemented", "planned"
N, ILL, EMP = "n/a", "illustrative", "empirically calibrated (none yet)"

# (identifier, description, type, units, default, allowed range, validation, security, location, status, calibration)
SECTIONS: list[tuple[str, list[tuple]]] = [
 ("Source identity", [
  ("manifest_version", "Snapshot manifest format version", "int", "-", "1", ">=1", "must equal supported version", "version confusion would let old manifests be parsed under new rules", "snapshots.MANIFEST_VERSION", I, N),
  ("snapshot.entries[].path", "Relative path of a file in a snapshot", "str", "-", "-", "<=1024 chars; no '..', '.', empty or absolute components; no backslash/NUL/control chars", "snapshots.validate_rel_path; NFC+casefold collision check", "path traversal / escape; case-colliding files", "snapshots.py", I, N),
  ("snapshot.entries[].digest", "SHA-256 of file content", "digest", "hex", "-", "64 lowercase hex", "blob must exist in CAS and re-hash correctly", "source identity depends on it", "snapshots.verify_snapshot", I, N),
  ("snapshot.entries[].executable", "Owner-executable bit", "bool", "-", "false", "true/false", "part of identity", "execute-bit changes alter behavior so alter identity", "snapshots.build_entries", I, N),
  ("DEFAULT_EXCLUDES", "Glob names omitted from snapshots (VEP state, VCS dirs, caches, credential-like files)", "tuple[str]", "glob", ".vep .git __pycache__ .env *.pem *.key id_rsa* ...", "fnmatch patterns", "matched on every path component", "keeps private state and credentials out of staging", "snapshots.DEFAULT_EXCLUDES", I, N),
  ("MAX_FILE_BYTES", "Largest file a snapshot will ingest", "int", "bytes", "16777216", ">0", "checked in scan_tree", "resource exhaustion", "snapshots.py", I, ILL),
  ("MAX_PATH_LEN", "Longest permitted relative path", "int", "chars", "1024", ">0", "validate_rel_path", "resource exhaustion", "snapshots.py", I, ILL),
  ("symlink policy", "All symlinks and special files are rejected", "rule", "-", "reject", "fixed", "lstat check", "symlink escape out of the tree", "snapshots.scan_tree", I, N),
 ]),
 ("Artifact storage", [
  ("cas.root", "CAS directory", "path", "-", ".vep/cas", "inside .vep", "created 0755; objects 0444", "state must live outside staged trees", "storage.CAS", I, N),
  ("cas.digest", "Address of an object", "digest", "hex", "-", "64 lowercase hex", "regex-checked before any path is built; content re-hashed on get", "blocks traversal and filename spoofing", "storage.CAS._path/get", I, N),
  ("cas.write_mode", "Atomic temp-file + fsync + rename; duplicate puts skip when content verifies", "rule", "-", "atomic", "fixed", "tests in test_storage", "torn writes; corruption repair on rewrite", "storage.CAS.put", I, N),
 ]),
 ("Object serialization", [
  ("CANON_VERSION", "Canonical serialization version (VEP-C1)", "int", "-", "1", "1", "documented in RFC-0001", "changing it changes every identity", "canonical.py", I, N),
  ("SCHEMA_VERSION", "Object schema version embedded in every object and identity domain", "int", "-", "1", "1", "from_bytes rejects other versions", "domain separation across versions", "objects.SCHEMA_VERSION", I, N),
  ("identity.domain", "Hash domain string `vep.<Type>.v<schema_version>`", "str", "-", "-", "fixed per type", "length-prefixed in domain_hash", "prevents cross-type identity collisions", "canonical.domain_hash", I, N),
  ("MAX_INT", "Largest permitted JSON integer magnitude", "int", "-", "2^63-1", "fixed", "_check", "cross-language integer ambiguity", "canonical.py", I, N),
  ("MAX_DEPTH", "Maximum JSON nesting", "int", "levels", "64", "fixed", "_check", "stack exhaustion", "canonical.py", I, ILL),
  ("float policy", "Floats, NaN and Infinity are rejected everywhere in canonical data", "rule", "-", "reject", "fixed", "strict_loads hooks", "ambiguous money and non-finite numbers", "canonical.strict_loads", I, N),
  ("duplicate-key policy", "Duplicate JSON object keys rejected", "rule", "-", "reject", "fixed", "object_pairs_hook", "parser-differential attacks", "canonical.strict_loads", I, N),
  ("timestamp format", "UTC `YYYY-MM-DDTHH:MM:SSZ`", "str", "UTC", "-", "regex", "objects.TS_RE", "timestamps are descriptive, never trusted for ordering", "objects.py", I, N),
  ("decimal format", "Decimal strings for money/probabilities", "str", "-", "-", "`-?\\d+(\\.\\d+)?`", "objects.DEC_RE", "avoids float rounding in money", "objects.py", I, N),
 ]),
 ("Cryptographic policies", [
  ("signature.algorithm", "Ed25519 via the `cryptography` package; no custom crypto", "rule", "-", "Ed25519", "fixed", "evidence.open_envelope", "algorithm agility attacks avoided by fixing it", "evidence.py", I, N),
  ("signature.envelope", "DSSE-style PAE over payloadType and payload; exactly one signature", "rule", "-", "DSSEv1 PAE", "fixed", "evidence._pae", "binds payload type to signature", "evidence.py", I, N),
  ("PAYLOAD_TYPE", "Envelope payload type", "str", "-", "application/vnd.vep.object+json;v=1", "fixed", "must match exactly", "type confusion", "evidence.PAYLOAD_TYPE", I, N),
  ("signing key file", "Ed25519 private key (PEM, unencrypted)", "path", "-", ".vep/keys/signing.pem", "mode 0600 required", "KeyStore._load refuses group/world access", "same-OS-user code can read it: NOT protected from trusted-local candidates", "evidence.KeyStore", I, N),
  ("trusted_keys", "Registry of verification keys (key_id = SHA-256 of raw public key)", "table", "-", "created at init", "revocable flag", "open_envelope looks up keys here, never in the envelope", "forged or revoked keys fail", "database.py", I, N),
  ("key rotation / external signer / HSM", "Rotation workflow, remote signer, hardware-backed keys", "-", "-", "-", "-", "-", "required for any production claim", "-", P, N),
 ]),
 ("Candidate states", [
  ("candidate.status", "Lifecycle state", "enum", "-", "PROPOSED", "PROPOSED POLICY_CHECKED BUDGET_RESERVED EVALUATING EVIDENCE_READY CERTIFIED REJECTED", "ALLOWED edge table + SQL CHECK + triggers", "illegal edges and self-certification rejected", "candidates.ALLOWED; database.SCHEMA", I, N),
  ("candidate.version", "Optimistic-concurrency counter", "int", "-", "0", ">=0", "transition(expected_version) compare-and-swap", "stale/replayed operations rejected", "candidates.transition", I, N),
  ("transition.proof_id", "Evidence, certificate, action or reservation key justifying a transition", "str", "-", "null", "-", "DB triggers require PASS evidence / certificate rows for EVIDENCE_READY / CERTIFIED", "status alone never certifies", "database.SCHEMA triggers", I, N),
  ("transition.actor / reason", "Audit fields of the append-only log", "str", "-", "-", "non-empty", "UPDATE/DELETE blocked by trigger", "auditability", "database.SCHEMA", I, N),
  ("WorkClaim.paths / expires_at", "Paths an agent intends to modify and claim expiry", "list[str], ts", "-", "-", "relative paths", "claims_overlap prefix test", "advisory only; composition is re-evaluated regardless", "candidates.py", I, N),
 ]),
 ("Evaluation policies", [
  ("policy.name", "Human label of the frozen policy", "str", "-", "default", "non-empty", "part of identity", "-", "policies.make_policy", I, N),
  ("policy.policy_version", "Policy schema/semantics version", "int", "-", "1", ">=1", "-", "-", "policies.make_policy", I, N),
  ("policy.protected_patterns", "fnmatch globs a candidate may not add/modify/remove", "list[str]", "glob", "conftest.py */conftest.py pytest.ini tox.ini setup.cfg pyproject.toml unittest.cfg .coveragerc sitecustomize.py usercustomize.py *.pth .vep/* vep-policy*.json", "fnmatch on path or basename", "policies.check_candidate", "candidate cannot redefine acceptance procedure", "policies.DEFAULT_PROTECTED", I, ILL),
  ("policy.required_tests", "Map test-file path -> content digest frozen from the trusted base snapshot", "map[str,digest]", "-", "all tests matching evaluator", ">=1 entry", "must exist unchanged in the candidate and must execute", "candidate cannot replace or delete required suite", "policies.make_policy", I, N),
  ("policy.audits", "Policy-defined static audit specs", "list[object]", "-", "[]", "see Readiness invariants", "audits.run_audits_on_snapshot", "audit definitions live outside the candidate", "policies/audits", I, N),
  ("objective.policy_id", "Policy bound to an objective", "id", "-", "-", "existing ExecutionPolicy", "load_policy re-validates", "changing policy changes objective identity", "objectives.create_objective", I, N),
 ]),
 ("Execution restrictions", [
  ("trusted-local authorization", "Exact string required to run candidate code in a plain subprocess", "str", "-", "absent", "I-ACCEPT-NON-ISOLATED-EXECUTION", "execution.evaluate checks before any state change", "default is NO execution", "execution.TRUSTED_LOCAL_AUTH", I, N),
  ("evaluate.mode", "trusted-local | isolated", "enum", "-", "trusted-local", "isolated always fails closed in this MVP", "execution.evaluate", "no silent downgrade", "execution.py", I, N),
  ("evaluator.kind", "Restricted command grammar selector", "enum", "-", "unittest", "unittest | pytest", "policies.validate_evaluator", "no free-form shell commands exist", "policies.EVALUATOR_GRAMMAR", I, N),
  ("evaluator extra fields", "Any field outside the grammar", "-", "-", "-", "rejected", "validate_evaluator", "arbitrary commands cannot be smuggled", "policies.py", I, N),
  ("subprocess env", "Scrubbed environment: PATH=/usr/bin:/bin, HOME/TMPDIR in scratch, PYTHONDONTWRITEBYTECODE, PYTHONHASHSEED=0, PYTEST_DISABLE_PLUGIN_AUTOLOAD", "map", "-", "fixed", "fixed", "execution._safe_env", "no inherited secrets or PYTHONPATH", "execution.py", I, N),
  ("interpreter flags", "`python -I` (ignores PYTHON* env, user site, cwd/script dir on path)", "rule", "-", "-I", "fixed", "execution.build_argv", "blocks PYTHONPATH/usercustomize shadowing", "execution.py", I, N),
  ("sys.path policy", "Candidate import roots are appended, never prepended", "rule", "-", "append", "fixed", "_runner.py", "stdlib wins name resolution", "_runner.py", I, N),
  ("DENIED_MODULES", "Names a candidate may not add at an import root (stdlib names + runner/test-framework names)", "frozenset", "-", "sys.stdlib_module_names + pytest/_pytest/pluggy/...", "-", "policies.shadowing_paths", "runner/stdlib shadowing", "policies.py", I, N),
  ("staging", "Snapshot materialized read-only from the CAS into a fresh temp dir outside the workspace", "rule", "-", "read-only", "fixed", "snapshots.materialize; execution.evaluate", "candidate never sees .vep or the live tree", "execution.py", I, N),
  ("post-run integrity checks", "Staged tree re-hashed; key file digest compared", "rule", "-", "on", "fixed", "execution.evaluate", "detects workspace mutation and key tampering", "execution.py", I, N),
 ]),
 ("Test discovery", [
  ("evaluator.start_dir", "unittest discovery directory", "str", "path", "tests", "safe relative path", "validate_evaluator", "-", "policies.py", I, N),
  ("evaluator.pattern", "unittest discovery filename pattern", "str", "glob", "test*.py", "[A-Za-z0-9_*?.-]{1,64}", "PATTERN_RE", "pattern injection", "policies.PATTERN_RE", I, N),
  ("evaluator.targets", "pytest targets", "list[str]", "paths", "[tests]", "safe relative paths, non-empty", "validate_evaluator", "-", "policies.py", I, N),
  ("evaluator.import_roots", "Directories added to the import path", "list[str]", "paths", "[.]", "safe relative paths", "validate_evaluator", "must also be shadow-checked", "policies.py", I, N),
  ("evaluator.min_tests", "Minimum PASSED tests required", "int", "tests", "1", ">=1", "validate_evaluator; validate_report", "zero-test results can never pass", "execution.validate_report", I, ILL),
  ("false-green rules", "ZERO_TESTS, ALL_SKIPPED, REPORT_INCONSISTENT, EXIT_REPORT_MISMATCH, REQUIRED_SUITE_NOT_EXECUTED, REQUIRED_SUITE_ALL_SKIPPED, TOO_FEW_PASSING_TESTS, MALFORMED_REPORT", "rule", "-", "on", "fixed", "execution.validate_report", "exit code 0 alone never certifies", "execution.py", I, N),
 ]),
 ("Evidence validity", [
  ("Evidence.verdict", "PASS only if exit 0, no failures/errors, validations hold", "enum", "-", "-", "PASS | FAIL", "validate_report", "FAIL evidence is signed and rejects the candidate", "execution.py", I, N),
  ("Evidence bindings", "candidate, objective, snapshot, policy, action, runner digest, staged-tree snapshot id", "ids", "-", "-", "must equal the candidate's", "certify + verify_certificate", "evidence cannot be re-used for other sources/policies", "certificates.py", I, N),
  ("Evidence.isolation", "NONE_TRUSTED_LOCAL or DOCKER_GVISOR", "enum", "-", "NONE_TRUSTED_LOCAL", "enum", "recorded and surfaced by verify", "never misrepresent local runs as isolated", "execution.py", I, N),
  ("Evidence.stdout_digest / stderr_digest", "CAS digests of captured output (truncated to max_output_bytes)", "digest", "-", "-", "-", "-", "output retained for audit", "execution.py", I, N),
  ("runner_digest", "SHA-256 of the protected runner source", "digest", "-", "-", "-", "recorded in Action and Evidence", "detects runner substitution", "execution.runner_digest", I, N),
  ("report trust boundary", "Runner report is written by a process that also runs candidate code", "-", "-", "-", "-", "documented limitation", "hostile candidates could forge it; hence trusted-local only", "docs/THREAT_MODEL.md", I, N),
 ]),
 ("Certificates", [
  ("Certificate.snapshot_id", "Exact certified source identity", "id", "-", "-", "-", "verify --current compares live tree hash", "no inheritance by similar ids", "certificates.verify_certificate", I, N),
  ("Certificate.evidence_envelope_digest", "CAS digest of the signed evidence envelope", "digest", "-", "-", "-", "re-verified at certify and verify", "tamper-evident chain", "certificates.py", I, N),
  ("verify.current_root", "Directory hashed to confirm the live source equals the certificate", "path", "-", "workspace root", "-", "SOURCE_CHANGED on mismatch", "stale certificates rejected", "certificates.py", I, N),
  ("verify.expect_objective_id / expect_policy_id", "Caller-asserted bindings", "id", "-", "none", "-", "mismatch fails", "changed objective/policy cannot inherit", "certificates.py", I, N),
 ]),
 ("Token pricing", [
  ("prices_per_million.input", "USD per million ordinary input tokens", "decimal", "USD/Mtok", "-", ">=0", "tokens._dec", "stored with the receipt", "tokens.py", I, N),
  ("prices_per_million.cached_input", "USD per million cache-read tokens", "decimal", "USD/Mtok", "-", ">=0", "tokens._dec", "-", "tokens.py", I, N),
  ("prices_per_million.cache_write", "USD per million cache-write tokens", "decimal", "USD/Mtok", "-", ">=0", "tokens._dec", "-", "tokens.py", I, N),
  ("prices_per_million.output", "USD per million output tokens", "decimal", "USD/Mtok", "-", ">=0", "tokens._dec", "-", "tokens.py", I, N),
  ("pricing_version", "Label of the price table used", "str", "-", "-", "non-empty", "stored in receipt", "reproducibility of cost", "tokens.make_receipt", I, N),
  ("other_provider_charges", "Additional per-call charges", "decimal", "USD", "0", ">=0", "tokens._dec", "-", "tokens.py", I, N),
 ]),
 ("Token usage", [
  ("ordinary_input_tokens", "Uncached input tokens billed at the input price", "int", "tokens", "-", ">=0", "make_receipt", "-", "tokens.py", I, N),
  ("cached_input_tokens", "Tokens read from cache", "int", "tokens", "-", ">=0", "make_receipt", "-", "tokens.py", I, N),
  ("cache_write_tokens", "Tokens written to cache", "int", "tokens", "-", ">=0", "make_receipt", "-", "tokens.py", I, N),
  ("output_tokens", "Billed output tokens (includes reasoning)", "int", "tokens", "-", ">=0", "make_receipt", "-", "tokens.py", I, N),
  ("reasoning_tokens_in_output", "Reasoning tokens already inside output_tokens; never added to cost", "int", "tokens", "-", "0..output_tokens", "make_receipt", "prevents double counting", "tokens.py", I, N),
  ("usage_source", "provider_reported | simulated | local_estimate (mandatory, no default)", "enum", "-", "-", "enum", "make_receipt", "usage is caller-supplied and unauthenticated in this MVP", "tokens.py", I, N),
  ("idempotency_key", "Uniquely identifies a receipt", "str", "-", "-", "non-empty, unique", "token_receipts UNIQUE", "duplicate usage cannot be recorded twice", "tokens.record_receipt", I, N),
  ("receipt.status", "RECORDED | SETTLED", "enum", "-", "RECORDED", "enum", "-", "-", "objects.py", I, N),
 ]),
 ("Budget reservations", [
  ("account.kind", "organization | project | objective | candidate | operation", "enum", "-", "-", "child rank > parent rank", "create_account", "hierarchy cannot be inverted", "budgets.RANK", I, N),
  ("account.limit_micro", "Limit in micro-USD", "int", "1e-6 USD", "-", ">=0", "CHECK + to_micro", "integer arithmetic avoids float drift", "budgets.py", I, N),
  ("reservation.key", "Idempotency key of a reservation", "str", "-", "-", "unique; reuse with different params fails", "reserve", "duplicate requests cannot double-spend", "budgets.reserve", I, N),
  ("reservation.amount_micro", "Reserved funds", "int", "1e-6 USD", "-", ">0, <= available at every ancestor", "reserve under BEGIN IMMEDIATE", "no oversubscription under concurrency", "budgets.reserve", I, N),
  ("reservation.state", "RESERVED | SETTLED | RELEASED | UNCERTAIN", "enum", "-", "RESERVED", "enum", "settle/release/mark_uncertain", "uncertain outcomes keep funds held", "budgets.py", I, N),
  ("settle.settle_key / actual", "Idempotent settlement", "str, decimal", "USD", "-", "actual>=0 (ceil to micro)", "settle", "identical repeat is a no-op; conflict fails", "budgets.settle", I, N),
  ("overrun_micro", "max(0, actual - reserved), recorded", "int", "1e-6 USD", "0", ">=0", "settle + ledger OVERRUN", "actual spend is never hidden", "budgets.settle", I, N),
  ("limits.evaluation_cost_micro_usd", "Declared flat budget charged per local evaluation", "int", "1e-6 USD", "1000", ">=1", "validate_policy", "modelled, not measured compute cost", "policies.DEFAULT_LIMITS", I, ILL),
  ("org/project hierarchy levels", "Supported by the schema and tests via explicit accounts", "-", "-", "-", "-", "test_budgets", "-", "budgets.py", I, N),
 ]),
 ("Context budgets", [
  ("max_context_tokens", "Upper bound on manifest tokens", "int", "tokens", "-", ">=1", "build_context", "required paths that do not fit raise ContextBudgetExceeded", "context.py", I, N),
  ("token_method", "approx_utf8_bytes_div_4 (approximate) or measured", "enum", "-", "approx_utf8_bytes_div_4", "enum", "recorded in manifest", "approximation must be labeled", "context.BYTES_PER_TOKEN", I, ILL),
  ("entries[].reason", "required:explicit | required:policy-protected | requested | keyword:experimental", "str", "-", "-", "-", "-", "retrieval is explainable", "context.py", I, N),
  ("keyword_query", "Optional lexical retrieval (experimental, off by default)", "str", "-", "none", "-", "deterministic scoring", "not a trusted default; no measured benefit yet", "context.py", I, N),
  ("include_protected", "Always include policy-required tests", "bool", "-", "true", "-", "-", "protected requirements are never silently dropped", "context.py", I, N),
  ("semantic compression / embeddings", "Lossy compression or learned retrieval", "-", "-", "-", "-", "-", "not implemented; needs measured benefit first", "-", P, N),
 ]),
 ("Model routing", [
  ("ModelOption.price_in_per_m / price_out_per_m", "USD per million tokens", "decimal", "USD/Mtok", "-", ">=0", "ModelOption.from_dict", "supplied by operator", "routing.py", I, "supplied"),
  ("ModelOption.context_capacity", "Max tokens (input+output)", "int", "tokens", "-", ">0", "ineligible_reasons", "-", "routing.py", I, "supplied"),
  ("ModelOption.capabilities", "Capability tags", "set[str]", "-", "-", "-", "subset test", "-", "routing.py", I, "supplied"),
  ("ModelOption.acceptance_estimate", "A_cheap: P(output accepted by verification)", "decimal", "prob", "-", "[0,1]", "prob()", "point estimate; used for expected cost only", "routing.py", I, "supplied/simulated"),
  ("ModelOption.success_lower_bound", "Lower confidence bound on correct-and-accepted probability", "decimal", "prob", "-", "[0,1]", "prob()", "used for quality eligibility", "routing.py", I, "supplied/simulated"),
  ("ModelOption.false_accept_upper", "Upper bound on P(incorrect output accepted)", "decimal|null", "prob", "null", "[0,1]", "unmeasured => cascade ineligible", "no safety claim without measurement", "routing.py", I, "supplied"),
  ("ModelOption.latency_s / verification_cost / max_risk / evidence_source", "Latency, per-attempt verification cost (USD), risk ceiling, evidence label", "mixed", "s, USD", "-", "see from_dict", "from_dict", "evidence_source gates eligibility", "routing.py", I, "supplied"),
  ("Task.min_success_lower_bound", "Required quality bound", "decimal", "prob", "0.9", "[0,1]", "prob()", "-", "routing.Task", I, ILL),
  ("Task.max_false_accept", "Maximum tolerated cheap-model incorrect acceptance", "decimal", "prob", "0.01", "[0,1]", "prob()", "-", "routing.Task", I, ILL),
  ("Task.allowed_sources", "Evidence kinds accepted", "set", "-", "{measured}", "measured|simulated|supplied", "ineligible_reasons", "simulated numbers excluded by default", "routing.Task", I, N),
  ("Task.budget_available / max_latency_s / risk / token counts", "Budget, latency and risk constraints; request sizes", "mixed", "USD, s, tokens", "none", "-", "select", "worst-case cost must fit budget", "routing.Task", I, N),
  ("model reputation", "Not an input", "-", "-", "-", "-", "-", "reputation is not evidence", "-", "excluded", N),
 ]),
 ("Cache economics", [
  ("prefix_tokens / suffix_tokens / output_tokens", "Request composition", "int", "tokens", "-", ">=0", "CacheInputs.build", "-", "cache_planner.py", I, N),
  ("ordinary_input_price / output_price", "USD per million tokens", "decimal", "USD/Mtok", "-", ">=0", "CacheInputs.build", "output cost included in totals", "cache_planner.py", I, "supplied"),
  ("cache_write_multiplier", "Write price / ordinary input price", "decimal", "x", "-", ">=0", "CacheInputs.build", "-", "cache_planner.py", I, "supplied"),
  ("cache_read_multiplier", "Read price / ordinary input price", "decimal", "x", "-", "0..1", "CacheInputs.build", "values >1 unsupported", "cache_planner.py", I, "supplied"),
  ("expected_reuses", "Additional requests reusing the prefix", "int", "requests", "-", ">=0", "CacheInputs.build", "total requests n = reuses+1", "cache_planner.py", I, "supplied"),
  ("cache_lifetime_s / request_interval_s", "Provider TTL and inter-request gap", "decimal", "s", "none", ">=0", "plan()", "gap > TTL zeroes hit probability", "cache_planner.py", I, "supplied"),
  ("estimated_hit_probability", "Assumed hit probability on reuse", "decimal", "prob", "1", "[0,1]", "prob()", "assumption, not a guarantee; VEP cannot control provider caches", "cache_planner.py", I, "supplied"),
  ("break-even rule", "n > (w-m)/(1-m), m = h*r+(1-h)*w; h=1 gives (w-r)/(1-r); None if never", "rule", "requests", "-", "-", "break_even_requests", "denominator zero handled", "cache_planner.py", I, N),
 ]),
 ("Retries", [
  ("SimParams.retries", "Extra strong-model attempts after rejection (policy B)", "int", "attempts", "2", ">=0", "SimParams.validate", "-", "simulation.py", I, ILL),
  ("expected_retry_cost(max_attempts)", "Closed-form retry cost", "int|null", "attempts", "null", ">=1", "expected_retry_cost", "-", "simulation.py", I, N),
 ]),
 ("Concurrency", [
  ("SQLite write mode", "BEGIN IMMEDIATE, WAL, busy_timeout 60 s, one connection per operation", "rule", "-", "fixed", "fixed", "database.Database.tx", "serialized writers prevent oversubscription", "database.py", I, N),
  ("max_throughput(workers, mean_service_time_s)", "Stable-queue throughput bound c/E[S]", "int, decimal", "jobs/s", "-", "workers>=1, E[S]>0", "simulation.max_throughput", "-", "simulation.py", I, N),
  ("distributed coordination", "Multi-host leases, queues, consensus", "-", "-", "-", "-", "-", "NOT implemented; single-host invariants only", "-", P, N),
 ]),
 ("Scheduling", [
  ("order_tests(cost, p_fail)", "Order tests by p_fail/cost descending", "decimal", "s, prob", "-", "cost>0, p in [0,1]", "execution.order_tests", "-", "execution.py", I, N),
  ("queue discipline / merge queue / admission control", "Scheduling of candidates across workers", "-", "-", "-", "-", "-", "not implemented", "-", P, N),
 ]),
 ("Failure probabilities", [
  ("SimParams.cheap_base/cheap_slope/strong_base/strong_slope", "P(correct)=clamp(base-slope*difficulty)", "float", "prob", "0.80/0.70/0.97/0.25", "base in [0,1]", "SimParams.validate", "illustrative, NOT measurements of real models", "simulation.py", I, ILL),
  ("SimParams.verifier_sensitivity", "P(accept | correct)", "float", "prob", "0.98", "[0,1]", "validate", "illustrative", "simulation.py", I, ILL),
  ("SimParams.verifier_fp", "P(accept | incorrect)", "float", "prob", "0.10", "[0,1]", "validate", "drives incorrect acceptance", "simulation.py", I, ILL),
  ("SimParams.verifier_rho", "Dependence of second verifier's false accepts", "float", "-", "0.5", "[0,1]", "validate", "rho=1: second verifier adds nothing", "simulation.py", I, ILL),
  ("SimParams.difficulty", "uniform | hard_skew (Beta(3,1.5))", "enum", "-", "uniform", "enum", "validate", "-", "simulation.py", I, ILL),
 ]),
 ("Statistical experiments", [
  ("OptimizationExperiment.alpha", "Significance / FDR level", "decimal", "prob", "-", "decimal string", "objects", "-", "objects.py", I, N),
  ("OptimizationExperiment.data_source", "measured | simulated", "enum", "-", "-", "enum", "objects", "simulated evidence never labelled measured", "objects.py", I, N),
  ("OptimizationExperiment.adoption_rule / status", "Pre-declared adoption rule and lifecycle", "str, enum", "-", "-", "-", "objects", "no default adoption without measured benefit", "objects.py", I, N),
  ("benjamini_hochberg(pvalues, q)", "FDR-controlled rejections", "list[float], float", "prob", "-", "q in (0,1)", "simulation.py", "valid for independent / PRDS tests", "simulation.py", I, N),
 ]),
 ("Isolation", [
  ("isolation.image", "Digest-pinned image `name@sha256:<64 hex>`", "str", "-", "none", "IMAGE_RE", "build_plan/probe", "never pulled; must be local", "isolation.py", I, N),
  ("isolation flags", "--pull=never --runtime=runsc --network=none --read-only --cap-drop=ALL no-new-privileges non-root tmpfs ro bind mount", "rule", "-", "fixed", "fixed", "build_plan; test_isolation", "plan only: container execution NOT exercised", "isolation.build_plan", I, N),
  ("probe status", "ISOLATION_UNVERIFIED | ISOLATION_RUNTIME_PRESENT", "enum", "-", "-", "-", "isolation.probe", "RUNTIME_PRESENT is not an escape-resistance claim", "isolation.py", I, N),
  ("container evaluation pipeline", "Running the evaluator inside the container", "-", "-", "-", "-", "evaluate(mode='isolated') raises IsolationUnavailable", "UNVERIFIED / not implemented", "-", P, N),
 ]),
 ("Resource limits", [
  ("limits.timeout_s", "Wall-clock limit for the evaluator process group", "int", "s", "120", ">=1", "validate_policy; _run_limited kills process group", "TIMEOUT => REJECTED", "policies.DEFAULT_LIMITS", I, ILL),
  ("limits.max_output_bytes", "Captured stdout/stderr cap", "int", "bytes", "4000000", ">=1", "_run_limited", "log flooding", "policies.DEFAULT_LIMITS", I, ILL),
  ("isolation cpus / memory / pids / tmpfs", "Container limits in the plan", "str,int", "cpu, bytes, pids", "1 / 512m / 128 / 64m", "-", "build_plan", "plan only", "isolation.build_plan", I, ILL),
  ("local-process CPU/memory limits", "rlimits/cgroups for trusted-local runs", "-", "-", "-", "-", "-", "not implemented", "-", P, N),
 ]),
 ("Readiness invariants", [
  ("audit.id / audit.file", "Audit name and the JSON file (in the candidate snapshot) it inspects", "str", "-", "-", "file must exist and parse", "run_audits_on_snapshot", "missing/invalid file fails closed", "audits.py", I, N),
  ("rule aggregate_all", "aggregate flag must equal AND of component flags; min_components (default 1); strict booleans only", "object", "-", "-", "-", "evaluate_rule", "F12/F13", "audits.py", I, N),
  ("rule implies", "if-condition => then-condition (missing then-field fails)", "object", "-", "-", "-", "evaluate_rule", "F16", "audits.py", I, N),
  ("rule forbid_when", "forbid values of one path when another path matches", "object", "-", "-", "-", "evaluate_rule", "F14", "audits.py", I, N),
  ("rule forbid_values", "forbid substrings in a value/list (e.g. debug endpoints)", "object", "-", "-", "-", "evaluate_rule", "F15", "audits.py", I, N),
  ("rule require_present / min_value_count", "field existence; minimum collection size", "object", "-", "-", "-", "evaluate_rule", "-", "audits.py", I, N),
 ]),
 ("Feature flags", [
  ("(none)", "VEP itself defines no feature flags. Flag-consistency of audited products is checked via aggregate_all/implies rules", "-", "-", "-", "-", "-", "see Readiness invariants", "audits.py", "n/a", N),
 ]),
 ("Deployment gates", [
  ("certificate gate", "Verification of a certificate against current source is the only gate implemented", "rule", "-", "-", "-", "certificates.verify_certificate", "no deployment automation exists", "certificates.py", I, N),
  ("deployment automation / promotion pipelines", "-", "-", "-", "-", "-", "-", "not implemented", "-", P, N),
 ]),
 ("Observations", [
  ("Observation.value / unit / source", "A recorded datum; source is measured | simulated | supplied", "decimal, str, enum", "any", "-", "decimal string", "objects", "label prevents simulated data posing as measured", "objects.py", I, N),
 ]),
 ("Benchmark controls", [
  ("--seed / SimParams.seed", "Deterministic RNG seed (per task `Random(f'{seed}:{i}')`)", "int", "-", "20261019", "any int", "run twice => identical", "-", "simulation.py; benchmarks/run_simulation.py", I, N),
  ("--tasks / SimParams.n_tasks", "Synthetic tasks per run", "int", "tasks", "20000", ">=1", "validate", "-", "simulation.py", I, ILL),
  ("SimParams token/price fields", "in/out/verify tokens; cheap & strong prices (USD/Mtok)", "int, str", "tokens, USD/Mtok", "4000/1000/500; 0.25/1.25; 3/15", ">=0", "Decimal parse", "illustrative placeholders", "simulation.py", I, ILL),
  ("SimParams.router_noise / router_threshold", "Adaptive routing difficulty-estimate noise and cutoff", "float", "-", "0.15 / 0.5", "-", "-", "illustrative", "simulation.py", I, ILL),
  ("sensitivity grid", "fp {0.02,0.10,0.30} x rho {0,0.5,1}; price ratio {2,12,60}; difficulty; retries {0,2,5}", "grid", "-", "-", "-", "sensitivity()", "-", "simulation.py", I, ILL),
 ]),
 ("CLI and process", [
  ("exit codes", "0 ok; 1 generic; 2 usage; 3 policy/not selected; 4 verification failed; 5 budget; 6 context budget; 7 authorization; 8 isolation unverified; 9 false green; 10 canonical; 11 schema; 12 not found; 13 corrupt; 14 snapshot; 15 state; 16 execution; 70 unexpected", "int", "-", "-", "-", "errors.py; cli.main", "stable automation contract", "errors.py", I, N),
  ("--json / --root", "Machine-readable output; workspace root", "flag, path", "-", "off / cwd", "-", "cli._common", "keys are never printed", "cli.py", I, N),
 ]),
]

DESC = {
    "candidate_id": "Candidate this record concerns", "objective_id": "Objective this record concerns",
    "snapshot_id": "Snapshot (source identity)", "base_snapshot_id": "Trusted base snapshot", "policy_id": "Frozen ExecutionPolicy",
    "created_at": "Creation time (UTC, informational)", "created_by": "Creator label", "author": "Agent label",
    "title": "Short title", "description": "Free text", "paths": "Relative paths", "claimant": "Claiming agent",
    "expires_at": "Claim expiry (UTC)", "argv": "Argument vector (never a shell string)", "env": "Declared environment",
    "isolation": "Isolation level actually used", "runner_digest": "Digest of the protected runner",
}


def render() -> str:
    out = ["# VEP Variable Registry", "",
           "_Generated by `scripts/gen_variables.py` from the code schemas and a curated list; a test fails if this file is stale._", "",
           "Columns: **Identifier | Description | Type | Units | Default | Allowed range | Validation rules | Security implications | Implementation location | Status | Calibration**.",
           "`Status`: implemented / planned / excluded. `Calibration`: `n/a` for structural rules, `illustrative` for placeholder numbers, "
           "`supplied` for operator-provided inputs. No parameter in this MVP is empirically calibrated against real-world data.", ""]
    for title, rows in SECTIONS:
        out += [f"## {title}", "", "| Identifier | Description | Type | Units | Default | Allowed range | Validation rules | Security implications | Location | Status | Calibration |",
                "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
        out.append("")
    out += ["## Object schema fields (generated from `objects.SPECS`)", "",
            "All fields are validated by `VEPObject.create`; unknown fields are rejected; optional fields are omitted when absent (never null). "
            "Security: every field is part of the object's identity, so changing any field yields a new identity. Status: implemented. Calibration: n/a.", ""]
    for tname, spec in objects.SPECS.items():
        out += [f"### {tname} (id prefix `{spec['prefix']}-`)", "", "| Field | Kind | Required | Options | Description |", "|---|---|---|---|---|"]
        for fname, (kind, req, opts) in spec["fields"].items():
            o = ", ".join(f"{k}={v}" for k, v in opts.items()) or "-"
            out.append(f"| {tname}.{fname} | {kind} | {'yes' if req else 'no'} | {o} | {DESC.get(fname, fname.replace('_', ' '))} |")
        out.append("")
    out += ["## Policy structure (generated)", "", f"* Evaluator grammar: `{ {k: sorted(v) for k, v in policies.EVALUATOR_GRAMMAR.items()} }`",
            f"* Default limits: `{policies.DEFAULT_LIMITS}`", ""]
    return "\n".join(out)


def main() -> int:
    target = ROOT / "docs" / "VARIABLES.md"
    text = render()
    if "--check" in sys.argv:
        return 0 if target.exists() and target.read_text() == text else 1
    target.write_text(text)
    print(f"wrote {target} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
