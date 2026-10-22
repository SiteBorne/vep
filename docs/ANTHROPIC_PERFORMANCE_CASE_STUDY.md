# VEP performance case study (one page, internal draft; not submitted)

**Question.** Does a signed, independently verifiable test certificate cost too much to be useful in an agent loop?

**Method.** Preregistered A/B on GitHub-hosted Linux (4 vCPU): a pristine control checkout and each optimization arm run in the same randomized, warmed-up blocks; Welch 95% intervals plus a paired bootstrap; rule fixed in advance (10% and 50 ms). Four runs preserved. Real projects: pyflakes 4.0.3 and more-itertools v11.2.1; synthetic trees of 100-8,000 files.

**What the numbers say (mechanisms, not marketing).**
- A fresh certificate costs 1.45× a direct run on short tests (1.06 s vs 0.73 s) and 1.03× on long ones (11.3 s vs 11.0 s). The overhead is fixed per file; long-running tests hide it.
- Removing redundant integrity passes and speeding staging cut CPU by 12-20% on large trees in all four runs and wall time by roughly 11-18% on the two quiet runs. The qualifying run was too noisy to confirm the wall-time result, so this is **inconclusive under the preregistered rule and not claimed**.
- Reflink staging never activated on the hosted filesystem (ext4); no gain is claimed for it.
- Exact-input reuse converts identical re-verification into an attestation in about half the time, and is labelled as an attestation, not a fresh certificate.
- Throughput scales to the core count; every candidate was certified exactly once.

**What is not claimed.** Nothing about tokens, API cost or model behaviour was measured. No percentage is presented as a headline. Scion's design was compared by mechanism only; no cross-system timing was made.

**Evidence.** `docs/AGENT_SCALE_PERFORMANCE_REPORT.md`; raw artifacts in `benchmarks/results/hosted-linux-perf-run-*/`; hosted runs 39719640989, 39721614817, 39747018211, 39755218641.
