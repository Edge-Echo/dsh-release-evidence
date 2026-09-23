# Changelog

## 0.1.0

First release. **Aggregation and verification, not another test runner**: it does not run
`dsh-testkit`, `dsh-eval-harness` or a compatibility check — it packs what they produced into
one signed artifact and states plainly what was not checked.

- `collect` discovers evidence without configuration: `.dsh-testkit/runs/**/report.json` and
  `junit.xml`, eval-harness reports, compatibility and quality-budget JSON, `*.tgz`. Verdicts are
  read from the artifacts themselves — JUnit XML gets a real attribute parser because
  `failures="0"` would otherwise trip a keyword scan. Artifacts older than `--max-age-days` are
  skipped with the reason recorded.
- `pack` digests every artifact, covers the digests with one RFC 6962 Merkle root, and signs the
  result with Ed25519 when given a key.
- `verify` is the third party's entry point: it re-checks digests, the root, the signature,
  completeness, failing evidence and expiry, and exits non-zero. `--require-complete` makes the
  two required kinds (lifecycle evidence and the packed artifact) mandatory.
- `EVIDENCE.md` renders what was checked *and* what is absent, with the tool that normally
  produces each missing kind.
- `action.yml` runs the lifecycle gate, packs, verifies and uploads, failing the job when
  required evidence is missing.

Verified by 13 unit tests covering the paths a reviewer depends on (edited report, added or
reordered entry, rewritten subject, unsigned pack, missing required evidence, failing report,
expired pack, cross-pack replay) and 24 end-to-end CLI checks over a fixture repository.

The only runtime dependency is `@edge-echo/dsh-ledger`, used for the Merkle tree; it has no
dependencies of its own.
