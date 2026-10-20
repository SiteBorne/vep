# Roadmap

No dates. Ordered by how much each item would change what can honestly be claimed.

1. Re-run the benchmarks on a quiet machine and publish the numbers ([BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md) records the deviation).
2. Independent review of the wire format and the verifier (a third implementation or an outside reader), and a Go verifier.
3. Observe the sandbox from inside the container (strengthen T12); add escape-oriented tests; run the matrix on more than one runner image.
4. Add the shadow check to the pytest evaluator; wire cross-candidate evidence reuse for identical snapshots (needs an evidence schema decision).
5. Evaluate a project with real third-party dependencies and an autonomous-agent-authored change (the VEP-on-VEP change was written interactively).
6. Replace illustrative routing/cache parameters with calibrated ones from measured runs.
7. Key rotation, an external signer or transparency log.
8. Remote execution adapter (REAPI) tested against a real server.
9. Publish a package release (`0.5.0b1`) once the launch gate allows it.

Not planned: a hosted service, a new build system, a new cryptographic protocol.
