# dsh-release-evidence

**One verifiable artifact per release.** It does not run your tests — it proves which
checks ran, what they concluded, and that their reports have not been altered since.

```
dsh-evidence pack     # → .dsh-evidence/evidence.json + EVIDENCE.md (+ Ed25519 signature)
dsh-evidence verify   # → a third party checks it without trusting your CI
```

[![npm version](https://img.shields.io/npm/v/dsh-release-evidence?color=10b981&logo=npm)](https://www.npmjs.com/package/dsh-release-evidence)
[![license](https://img.shields.io/badge/license-MIT-6ee7b7)](LICENSE)

> Part of the **dsh-toolkit family**: [dsh-mcp-bridge](https://github.com/Edge-Echo/dsh-mcp-bridge) · [dsh-win-toolkit](https://github.com/Edge-Echo/dsh-win-toolkit) · [dsh-netassist](https://github.com/Edge-Echo/dsh-netassist) · [dsh-driftwatch](https://github.com/Edge-Echo/dsh-driftwatch) · [mcp-netassist](https://github.com/Edge-Echo/mcp-netassist) · [dsh-ledger](https://github.com/Edge-Echo/dsh-ledger) · [dsh-release-evidence](https://github.com/Edge-Echo/dsh-release-evidence)

---

## The problem

A DSH plugin can compile, pass unit tests, and still fail after publication — files missing
from the tarball, a peer that does not resolve, a lifecycle stage that only breaks in a real
host. The ecosystem already has tools that answer those questions:

| tool | answers |
|---|---|
| `dsh-testkit` | does the plugin survive a real host install → register → exercise → uninstall? |
| `dsh-eval-harness` | do the YAML regression cases still match the baseline? |
| `dsh-plugin-compat-check` | do the peer versions resolve? |
| `dsh-cordis-plugin-kit` | does it fit the size and dependency budgets? |

Each writes its own report, in its own format, into its own directory. What has been missing
is one artifact a reviewer — or a marketplace — can check **without trusting the CI run that
produced it**, and which states plainly what was *not* checked.

## What this does

```
$ dsh-evidence pack --pack-tarball --key release-key.pem

packed 3 artifact(s) from 6 scanned file(s)
  subject        : dsh-driftwatch@0.1.1 (b149219)
  evidence root  : e117cc029c4caee6d5cc65be4e7fcacf5c171e837313d59e5f96b8cb626c1948
  signed         : yes (Ed25519)
  complete       : true
  wrote .dsh-evidence/evidence.json
  wrote .dsh-evidence/EVIDENCE.md
```

And a verifier, who needs nothing from your machine:

```
$ dsh-evidence verify .dsh-evidence --require-complete

subject: dsh-driftwatch@0.1.1
verification: OK
  complete=true signature=true digests=true root=true stale=false
```

Three properties make that a check rather than a claim:

1. **Every artifact is digested, and the digests are covered by one Merkle root.** A report
   swapped, added, removed or reordered after packing changes the root — and editing a report
   in place is caught by its own digest.
2. **The pack is Ed25519-signed**, so it also pins who attested it, and rewriting the subject
   (for example, claiming a different version) invalidates the signature.
3. **Verification reports what is missing.** Lifecycle evidence and the packed tarball are
   required; a pack without them verifies as `complete=false`, not as `ok`. A report that says
   `failed` fails the pack. A pack past its expiry is `stale`.

## Install

```bash
npm install -D dsh-release-evidence
```

## Use

```bash
dsh-evidence collect --root .          # what would be picked up, and what is missing
dsh-evidence keygen --out release-key.pem
dsh-evidence pack --root . --out .dsh-evidence --pack-tarball --key release-key.pem
dsh-evidence verify .dsh-evidence --root . --require-complete
```

`collect` needs no configuration for the known tools — it recognises what they write:

| evidence kind | required | recognised paths |
|---|---|---|
| `lifecycle-test` | yes | `.dsh-testkit/runs/**/report.json`, `junit.xml`, `report.md` |
| `packed-artifact` | yes | `*.tgz` (or produced by `--pack-tarball`) |
| `regression-eval` | no | `eval-harness*.json`, `eval-report.md` |
| `compatibility` | no | `compat-check*.json` |
| `quality-budget` | no | `quality-budget*.json` |
| `security-audit` | no | `security-audit*.json`, or any path you add with `--include` |
| `build-output` | no | `tsc-output.txt` |

Artifacts older than `--max-age-days` (default 14) are skipped, and the pack says so — a
year-old report does not become current by being packed.

### GitHub Action

```yaml
- uses: Edge-Echo/dsh-release-evidence@main
  with:
    dsh-version: '0.15.3'
    suite: full
    signing-key: ${{ secrets.DSH_EVIDENCE_KEY }}
    require-complete: 'true'
```

It runs the lifecycle gate, packs whatever evidence exists, verifies the pack as a third party
would, and uploads it as a build artifact.

## What a pack does **not** claim

- It is not a statement that the plugin is good. It is a statement that **specified checks
  produced specified results for a specified build**.
- It does not cover anything absent from its table — absent kinds are listed explicitly under
  *Not included*, with which tool normally produces them.
- An unsigned pack is not `ok`. Signing is what lets a reviewer attribute the attestation to
  a key rather than to whoever uploaded the file.
- A signature proves the pack was assembled by the key holder and not altered since. It does
  not prove the key holder ran the tools honestly on this machine.

## Verified behaviour

`npm test` covers the paths a reviewer depends on: an edited report, an added or reordered
entry, a rewritten subject, an unsigned pack, missing required evidence, a failing report, an
expired pack, and cross-pack entry replay. `npm run verify` drives the CLI end to end over a
fixture repository.

Built on [`@edge-echo/dsh-ledger`](https://github.com/Edge-Echo/dsh-ledger) for the Merkle
tree (`RFC 6962`). That is the only runtime dependency, and it has none of its own.

## License

MIT
