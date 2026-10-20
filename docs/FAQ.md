# FAQ

**Does VEP call an AI model?** No. The core never calls a model. An adapter interface and two adapters exist (an allowlisted subprocess adapter and an Ollama-compatible local adapter). One live run with a local 7B model produced a change that VEP certified ([REAL_WORLD_RESULTS.md](REAL_WORLD_RESULTS.md)); that is one run, not a reliability measure.

**Is it faster than my CI?** No, not for a single check; see [COMPARISON.md](COMPARISON.md). It is for evidence and accounting, not speed.

**Can I run untrusted code through it?** Not on the basis of anything verified here. See [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md).

**What does a certificate prove?** That a trusted key signed evidence and a certificate that agree with each other, at a stated trust level, for one exact source snapshot id. It does not prove the tests are good. In one external project a mutant (a one-line logic inversion) was caught by 43 tests [C:mit-mutant] failing tests of the project's own suite and in another by 259 tests [C:pyflakes-mutant]; that depends entirely on the project's tests.

**How do I check a certificate without VEP?** Export a bundle (`vep conformance export`) and verify it with any implementation of [CONFORMANCE.md](CONFORMANCE.md); `conformance/node/verify.mjs` needs only Node.

**Did you test it on real code?** Yes, locally: on its own repository (365 tests [C:dogfood-tests] passed in the final run), and on two small open-source projects at pinned commits ([docs/external](external/README.md)). Not on a project with third-party dependencies.

**Is there a hosted dashboard or account?** No. Everything is local files and SQLite.

**Does it work with Git?** It reads Git state (read-only) and never commits, pushes or merges.

**Which license?** Apache-2.0.
