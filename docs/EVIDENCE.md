# Evidence, Derivations and References

Legend — **Proof**: derived below, checked by a unit test. **Experiment**: depends on data; here only *simulated*. **Cited**: external result used for motivation, not re-derived.

## 1. Derivations (proofs)

### 1.1 Expected retry cost (geometric)
Attempts are independent with success probability p, cost c each, and are repeated until success. Attempts N ~ Geometric(p): E[N] = 1/p, so E[C] = c/p. With at most k attempts the expected number of attempts made is Σ_{i=0}^{k-1} (1-p)^i = (1-(1-p)^k)/p, so E[C_k] = c(1-(1-p)^k)/p. *Assumption:* independence — correlated retries (same model, same defect) break it. Test: `tests/test_math.py::MathTests.test_expected_retry_cost_geometric` (+ Monte-Carlo agreement).

### 1.2 Cheap-first cascade
E[C] = C_cheap + (1-A_cheap)·C_strong, where A_cheap is the probability the cheap output is *accepted by verification*, and each C includes its verification cost. It says nothing about correctness: an accepted-but-wrong output is a false acceptance with probability bounded only by the verifier's measured false-accept rate. Test: `tests/test_routing.py::RoutingTests.test_cascade_formula_exact`.

### 1.3 Cache break-even
Per unit of prefix price: n uncached requests cost n; cached costs w + (n-1)r (one write, n-1 reads). Cached < uncached ⇔ n(1-r) > w - r ⇔ n > (w-r)/(1-r) for r<1 (n counts the writing request; reuses = n-1). If r = 1 caching wins only when w < 1. With hit probability h a reuse costs m = h·r + (1-h)·w and the same formula holds with r→m; if m ≥ 1 and w ≥ 1 caching never pays. Suffix and output costs are identical on both sides, so they shift totals but not the break-even. Tests: `tests/test_cache.py`.

### 1.4 Budget conservation and idempotency
Invariant: for every account a, Σ_{reservations in scope(a)} hold(r) ≤ limit(a) at every committed state, where hold = amount (RESERVED/UNCERTAIN), actual (SETTLED), 0 (RELEASED). `reserve` checks every ancestor and commits inside one `BEGIN IMMEDIATE` transaction, so writers are serialized and the check-then-insert is atomic ⇒ the invariant is preserved by induction on committed transactions. Settlement can exceed the hold (actual spend is real); it is recorded as overrun and then available ≤ 0 blocks all new reservations. Idempotency: operations are keyed; a repeat with identical parameters returns the stored row, a conflicting repeat raises. Tests: `tests/test_budgets.py`.

### 1.5 Content-addressed deterministic execution
Action id = H(input snapshot id, policy id, runner digest, environment, isolation). If the evaluator is a deterministic function of those inputs, equal ids imply equal results, so a result can be reused; any change to source, policy or runner changes the id. Caveat: test suites that depend on time, randomness or the network are not functions of the id — reuse is therefore opt-in via `cached_evidence`, which re-verifies the signature. Test: F11 in `tests/test_adversarial.py`.

### 1.6 Test ordering
For independent checks i with cost c_i and failure probability p_i, stopping at the first failure, the expected cost of order π is Σ_j c_{π(j)} Π_{i<j}(1-p_{π(i)}). Exchange argument: swapping adjacent a,b changes the cost by c_a·(...)·[1 - (1-p_a)·... ] reducing to the sign of c_a p_b - c_b p_a, so a before b is optimal iff p_a/c_a ≥ p_b/c_b. Sorting by p/c descending is optimal under independence. Implemented in `execution.order_tests`; tested for the ordering outcome.

### 1.7 Queue throughput and Little's Law
L = λW holds for any stable system in steady state with long-run averages (Little 1961); it is distribution-free but says nothing about transient behaviour or about stability. A pool of c workers with mean service time E[S] is stable only if λ < c/E[S] (utilization ρ < 1), hence the throughput bound `max_throughput`. Tests: `tests/test_math.py`.

### 1.8 False acceptance with two verifiers
Let fp₁ be the first verifier's P(accept | incorrect) and fp₂ the second's. Define dependence ρ∈[0,1] by P(accept₂ | accept₁, incorrect) = fp₂ + ρ(1-fp₂). Then P(false accept) = fp₁(fp₂ + ρ(1-fp₂)): independent (ρ=0) gives fp₁·fp₂, fully dependent (ρ=1) gives fp₁ — the second verifier adds nothing. ρ is a *modeling parameter*, not a measured quantity. Test: `tests/test_math.py::MathTests.test_false_acceptance_dependence`.

### 1.9 Multiple testing
When many routing/caching/context variants are compared, uncorrected significance inflates false discoveries (m tests at level α yield ≈ mα expected false positives under the global null). Benjamini–Hochberg controls the false discovery rate at q for independent (or PRDS) p-values: reject the k smallest where k = max{i : p_(i) ≤ i·q/m}. Implemented in `simulation.benjamini_hochberg`; tested on a textbook example. An `OptimizationExperiment` must declare its adoption rule before data are seen; no optimization is adopted as a default in this MVP.

## 2. Experiments
Only the synthetic simulation (`docs/BENCHMARKS.md`). **All SIMULATED.** No measurement of any real model, verifier, price, cache or CI system exists in this repository.

## 3. References

"Verified" = the existence, title and identifier were confirmed by web search during this build (title/identifier only; claims were not audited). "Cited from knowledge" = standard references recalled by the author and **not re-fetched in this build**; confirm before relying on bibliographic details.

| Foundation | Reference | Status |
|---|---|---|
| Git | Git documentation, https://git-scm.com/doc | Cited from knowledge |
| Bazel Remote Execution API | https://github.com/bazelbuild/remote-apis | Cited from knowledge |
| Build Systems à la Carte | Mokhov, Mitchell, Peyton Jones, Proc. ACM Program. Lang. 2 (ICFP), 2018 | Cited from knowledge |
| SLSA | https://slsa.dev | Cited from knowledge |
| in-toto | Torres-Arias et al., "in-toto: Providing farm-to-table guarantees for bits and bytes", USENIX Security 2019; https://in-toto.io | Cited from knowledge |
| DSSE | https://github.com/secure-systems-lab/dsse | Cited from knowledge |
| Ed25519 | RFC 8032 | Cited from knowledge |
| SHA-256 | NIST FIPS 180-4 | Cited from knowledge |
| SQLite transactions | https://www.sqlite.org/lang_transaction.html | Cited from knowledge |
| Little's Law | J. D. C. Little, "A Proof for the Queuing Formula: L = λW", Operations Research 9(3), 1961 | Cited from knowledge |
| FrugalGPT | Chen, Zaharia, Zou, arXiv:2305.05176 | Cited from knowledge |
| RouteLLM | Ong et al., arXiv:2406.18665 | Cited from knowledge |
| SWE-Pruner | "SWE-Pruner: Self-Adaptive Context Pruning for Coding Agents", arXiv:2601.16746 | **Verified** (search) |
| CooperBench | "CooperBench: Why Coding Agents Cannot be Your Teammates Yet", arXiv:2601.13295 | **Verified** (search) |
| PagedAttention | Kwon et al., SOSP 2023, arXiv:2309.06180 | Cited from knowledge |
| SGLang / RadixAttention | Zheng et al., arXiv:2312.07104 | Cited from knowledge |
| Benjamini–Hochberg | J. R. Stat. Soc. B 57(1):289–300, 1995 | Cited from knowledge |
| Toyota Production System | T. Ohno, *Toyota Production System: Beyond Large-Scale Production*, 1988 | Cited from knowledge |
| Kubernetes reconciliation | Kubernetes documentation on controllers; Burns et al., "Borg, Omega, and Kubernetes", ACM Queue 14(1), 2016 | Cited from knowledge |
| Google Omega | Schwarzkopf et al., "Omega: flexible, scalable schedulers for large compute clusters", EuroSys 2013 | Cited from knowledge |

VEP uses these as design motivation; it does not reproduce their results and makes no claim about their reported numbers.
