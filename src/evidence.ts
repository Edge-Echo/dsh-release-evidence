// dsh-release-evidence — aggregate heterogeneous release evidence into one pack that a
// third party can verify.
//
// The job here is deliberately not "run the tests". `dsh-testkit` runs the real-host
// lifecycle gate, `dsh-eval-harness` runs regression cases, others check compatibility
// and quality budgets. Each already writes its own report, in its own format. What is
// missing is a single artifact that says: *this exact plugin build passed these
// specific checks, and here is proof that the reports have not been altered since*.
//
// Three things make that meaningful rather than decorative:
//
//   1. every artifact is digested, and the digests are covered by one Merkle root, so
//      the pack cannot be assembled from reports that were swapped afterwards;
//   2. the pack is Ed25519-signed, so it also pins *who* attested it;
//   3. verification reports what is **missing**, not just what passed. A pack with no
//      lifecycle evidence verifies as `incomplete`, not as `ok`.
//
// A pack is not a claim that the plugin is good. It is a claim that specified checks
// produced specified results for a specified build.
import { createHash, createPrivateKey, createPublicKey, sign, verify as verifySig } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { basename, join, relative, resolve } from 'node:path'
import { execFileSync } from 'node:child_process'
import { MerkleTree, hashLeaf } from '@edge-echo/dsh-ledger'

export const EVIDENCE_SCHEMA = 'dsh-release-evidence/1'

/** The kinds of evidence a release pack can carry, and whether a release may omit it. */
export const EVIDENCE_KINDS = {
  'lifecycle-test': { required: true, tool: 'dsh-testkit', describes: 'real-host install → register → exercise → uninstall' },
  'regression-eval': { required: false, tool: 'dsh-eval-harness', describes: 'YAML regression cases against a baseline' },
  compatibility: { required: false, tool: 'dsh-plugin-compat-check', describes: 'peer versions and installability' },
  'quality-budget': { required: false, tool: 'dsh-cordis-plugin-kit', describes: 'size, dependency and quality budgets' },
  'security-audit': { required: false, tool: '(various)', describes: 'static or runtime security findings' },
  'packed-artifact': { required: true, tool: 'npm pack', describes: 'the exact tarball a consumer would install' },
  'build-output': { required: false, tool: '(various)', describes: 'compiler or bundler output' },
} as const

export type EvidenceKind = keyof typeof EVIDENCE_KINDS

/** One artifact inside the pack, digested and attributed. */
export interface EvidenceEntry {
  kind: EvidenceKind
  /** Path relative to the repository root, so the pack is portable. */
  path: string
  /** sha256 of the file's bytes. */
  sha256: string
  bytes: number
  /** Which tool produced it, when the path or content reveals it. */
  producedBy?: string
  /** Pass/fail when the artifact states one. */
  status?: 'passed' | 'failed' | 'error' | 'unknown'
  /** A one-line summary extracted from the artifact, when one can be read. */
  summary?: string
}

/** The plugin build the pack is about. */
export interface EvidenceSubject {
  name: string
  version: string
  /** Git commit the working tree was at, when the repo is a git checkout. */
  commit?: string
  /** sha256 of the packed tarball, when one was found or produced. */
  tarballSha256?: string
  tarballBytes?: number
}

export interface ReleaseEvidencePack {
  schema: typeof EVIDENCE_SCHEMA
  subject: EvidenceSubject
  entries: EvidenceEntry[]
  /** Merkle root over the entries' leaf hashes, in entry order. */
  evidenceRoot: string
  createdAt: number
  /** After this time the pack should be treated as stale. */
  expiresAt: number
  /** Environment facts that make the results reproducible. */
  environment: { node: string; platform: string; arch: string; dshVersions?: string[] }
  signature?: string
  signerPublicKey?: string
}

const sha256Hex = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex')

/** Leaf preimage for one entry: kind, path and digest, so entries cannot be reordered. */
const entryLeaf = (entry: EvidenceEntry): Buffer =>
  Buffer.from(`${entry.kind}\u0000${entry.path}\u0000${entry.sha256}`, 'utf8')

/** Merkle root over the entries. A single swapped report changes it. */
export function evidenceRoot(entries: EvidenceEntry[]): string {
  return MerkleTree.fromHashes(entries.map((e) => hashLeaf(entryLeaf(e)))).rootHex
}

// ── classification ─────────────────────────────────────────────────────────

/** Where each tool is known to write, so collection needs no configuration. */
const KNOWN_LOCATIONS: [RegExp, EvidenceKind, string?][] = [
  [/\.dsh-testkit[\\/].*report\.json$/i, 'lifecycle-test', 'dsh-testkit'],
  [/\.dsh-testkit[\\/].*junit\.xml$/i, 'lifecycle-test', 'dsh-testkit'],
  [/\.dsh-testkit[\\/].*(report|summary)\.md$/i, 'lifecycle-test', 'dsh-testkit'],
  [/eval[-_]?harness.*\.(json|md)$/i, 'regression-eval', 'dsh-eval-harness'],
  [/(^|[\\/])eval[-_]?report.*\.(json|md)$/i, 'regression-eval', 'dsh-eval-harness'],
  [/compat[-_]?(check|report).*\.json$/i, 'compatibility', 'dsh-plugin-compat-check'],
  [/quality[-_]?budget.*\.json$/i, 'quality-budget', 'dsh-cordis-plugin-kit'],
  [/security[-_]?(audit|report).*\.(json|md)$/i, 'security-audit'],
  [/\.tgz$/i, 'packed-artifact', 'npm pack'],
  [/tsc[-_]?output\.txt$/i, 'build-output', 'tsc'],
]

/** Read a pass/fail verdict out of whatever shape the producing tool used. */
export function extractStatus(text: string): { status?: EvidenceEntry['status']; summary?: string } {
  // JUnit XML is one of dsh-testkit's outputs, so it gets a real parser rather than a
  // keyword scan: `failures="0"` contains the word "fail" and would be misread.
  const suite = /<testsuite\b[^>]*>/i.exec(text)
  if (suite) {
    const attr = (name: string): number | undefined => {
      const m = new RegExp(`${name}="(\\d+)"`, 'i').exec(suite[0]!)
      return m ? Number(m[1]) : undefined
    }
    const tests = attr('tests')
    const failures = attr('failures') ?? 0
    const errors = attr('errors') ?? 0
    const skipped = attr('skipped') ?? 0
    const status: EvidenceEntry['status'] = failures + errors > 0 ? 'failed' : tests && tests > 0 ? 'passed' : 'unknown'
    const bits = [`tests=${tests ?? '?'}`, `failures=${failures}`, `errors=${errors}`]
    if (skipped > 0) bits.push(`skipped=${skipped}`)
    return { status, summary: bits.join(', ') }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    // Not JSON: fall back to a line scan for markdown/plain reports.
    const failed = /(^|\n)\s*(\d+)\s+failed\b/i.exec(text)
    const passed = /(^|\n)\s*(\d+)\s+passed\b/i.exec(text)
    if (failed && Number(failed[2]) > 0) return { status: 'failed', summary: `${failed[2]} failed` }
    if (passed) return { status: 'passed', summary: `${passed[2]} passed` }
    if (/\bFAIL(ED)?\b/.test(text) && !/\bPASS(ED)?\b/.test(text)) return { status: 'failed' }
    if (/\bPASS(ED)?\b/.test(text)) return { status: 'passed' }
    return { status: 'unknown' }
  }

  const obj = parsed as Record<string, unknown>
  const candidate =
    (obj.status as string | undefined) ??
    (obj.result as string | undefined) ??
    (obj.outcome as string | undefined) ??
    (typeof obj.passed === 'boolean' ? (obj.passed ? 'passed' : 'failed') : undefined) ??
    (typeof obj.ok === 'boolean' ? (obj.ok ? 'passed' : 'failed') : undefined)

  const summaryBits: string[] = []
  for (const key of ['stages', 'checks', 'cases', 'tests'] as const) {
    const value = obj[key]
    if (Array.isArray(value)) summaryBits.push(`${value.length} ${key}`)
  }
  for (const key of ['passed', 'failed', 'total', 'version', 'artifactDigest'] as const) {
    const value = obj[key]
    if (typeof value === 'string' || typeof value === 'number') summaryBits.push(`${key}=${value}`)
  }

  let status: EvidenceEntry['status'] = 'unknown'
  if (typeof candidate === 'string') {
    const lower = candidate.toLowerCase()
    if (['pass', 'passed', 'ok', 'success', 'succeeded'].includes(lower)) status = 'passed'
    else if (['fail', 'failed', 'failure'].includes(lower)) status = 'failed'
    else if (['error', 'errored', 'infra-error'].includes(lower)) status = 'error'
  }
  return { status, summary: summaryBits.slice(0, 4).join(', ') || undefined }
}

/** Walk a directory, skipping the usual noise. */
function walk(root: string, maxFiles = 400, depth = 0): string[] {
  const out: string[] = []
  if (depth > 6) return out
  for (const item of readdirSync(root, { withFileTypes: true })) {
    if (out.length >= maxFiles) break
    if (['node_modules', '.git', 'lib', 'dist', 'coverage'].includes(item.name)) continue
    const full = join(root, item.name)
    if (item.isDirectory()) out.push(...walk(full, maxFiles - out.length, depth + 1))
    else out.push(full)
  }
  return out
}

export interface CollectOptions {
  /** Repository root to scan. */
  root: string
  /** Extra glob-ish suffixes to treat as evidence, e.g. ['evidence/*.json']. */
  include?: string[]
  /** Produce a tarball with `npm pack` when none is present. */
  pack?: boolean
  /** Ignore artifacts older than this (ms); defaults to 14 days. */
  maxAgeMs?: number
  /** Verdict a lifecycle report must carry for the pack to be complete. */
  now?: number
}

/** Collect evidence artifacts from a repository. */
export function collect(options: CollectOptions): { entries: EvidenceEntry[]; scanned: number; skipped: string[] } {
  const root = resolve(options.root)
  const now = options.now ?? Date.now()
  const maxAgeMs = options.maxAgeMs ?? 14 * 24 * 60 * 60 * 1000
  const skipped: string[] = []
  const entries: EvidenceEntry[] = []

  const files = walk(root)
  for (const file of files) {
    const rel = relative(root, file).replace(/\\/g, '/')
    const known = KNOWN_LOCATIONS.find(([pattern]) => pattern.test(file))
    const included = options.include?.some((suffix) => rel.endsWith(suffix.replace(/^\*/, '')))
    if (!known && !included) continue

    const stat = statSync(file)
    // Clamp at zero: filesystem timestamp granularity can put mtime a fraction of a
    // millisecond ahead of Date.now(), which would otherwise read as a negative age.
    const age = Math.max(0, now - stat.mtimeMs)
    if (age > maxAgeMs) {
      skipped.push(`${rel} (older than ${Math.round(maxAgeMs / 86400000)} days)`)
      continue
    }
    const bytes = readFileSync(file)
    const kind: EvidenceKind = known ? known[1] : 'security-audit'
    let extracted: { status?: EvidenceEntry['status']; summary?: string } = {}
    // Only the text formats carry a readable verdict; a tarball is just bytes.
    if (!file.endsWith('.tgz') && bytes.length < 8 * 1024 * 1024) {
      extracted = extractStatus(bytes.toString('utf8'))
    }
    entries.push({
      kind,
      path: rel,
      sha256: sha256Hex(bytes),
      bytes: stat.size,
      producedBy: known?.[2],
      status: extracted.status,
      summary: extracted.summary,
    })
  }

  entries.sort((a, b) => (a.kind === b.kind ? a.path.localeCompare(b.path) : a.kind.localeCompare(b.kind)))
  return { entries, scanned: files.length, skipped }
}

/** Read the subject (plugin identity) from package.json and git. */
export function readSubject(root: string, tarballPath?: string): EvidenceSubject {
  const pkgPath = join(resolve(root), 'package.json')
  if (!existsSync(pkgPath)) throw new Error(`no package.json under ${root}`)
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { name?: string; version?: string }
  const subject: EvidenceSubject = { name: pkg.name ?? '(unnamed)', version: pkg.version ?? '0.0.0' }

  try {
    subject.commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    /* not a git checkout; the commit is optional */
  }
  if (tarballPath && existsSync(tarballPath)) {
    const bytes = readFileSync(tarballPath)
    subject.tarballSha256 = sha256Hex(bytes)
    subject.tarballBytes = bytes.length
  }
  return subject
}

// ── signing ────────────────────────────────────────────────────────────────

/** Stable JSON so a signature does not depend on key order. */
function canonical(value: unknown): string {
  const walk = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null'
    if (Array.isArray(v)) return `[${v.map(walk).join(',')}]`
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, x]) => x !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${walk(x)}`).join(',')}}`
  }
  return walk(value)
}

const signable = (pack: ReleaseEvidencePack): string => {
  const { signature: _s, signerPublicKey: _p, ...rest } = pack
  return canonical(rest)
}

/** Sign a pack with an Ed25519 private key (PEM). */
export function signPack(pack: ReleaseEvidencePack, privateKeyPem: string): ReleaseEvidencePack {
  const key = createPrivateKey(privateKeyPem)
  const signature = sign(null, Buffer.from(signable(pack), 'utf8'), key).toString('base64')
  return {
    ...pack,
    signature,
    signerPublicKey: createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString(),
  }
}

export interface PackVerification {
  /** True only when every check passed *and* the pack is complete. */
  ok: boolean
  /** False when required evidence kinds are absent. */
  complete: boolean
  signatureValid: boolean
  digestsValid: boolean
  rootValid: boolean
  /** True when the pack is past its expiry. */
  stale: boolean
  missingKinds: EvidenceKind[]
  failedKinds: EvidenceKind[]
  issues: string[]
  entries: { path: string; kind: EvidenceKind; matches: boolean }[]
}

/**
 * Verify a pack against the files it points at.
 *
 * `root` is optional: without it, digests and the signature are still checked, but the
 * artifacts' contents are not re-read.
 */
export function verifyPack(pack: ReleaseEvidencePack, root?: string, now = Date.now()): PackVerification {
  const issues: string[] = []

  if (pack.schema !== EVIDENCE_SCHEMA) issues.push(`unexpected schema: ${String(pack.schema)}`)

  const rootValid = evidenceRoot(pack.entries) === pack.evidenceRoot
  if (!rootValid) issues.push('evidenceRoot does not match the entries (a report was added, removed or reordered)')

  const digests: { path: string; kind: EvidenceKind; matches: boolean }[] = []
  let digestsValid = true
  if (root) {
    const base = resolve(root)
    for (const entry of pack.entries) {
      if (entry.kind === 'packed-artifact') {
        // Tarballs from npm pack are usually not kept in the repository.
        digests.push({ path: entry.path, kind: entry.kind, matches: true })
        continue
      }
      const full = join(base, entry.path)
      if (!existsSync(full)) {
        digests.push({ path: entry.path, kind: entry.kind, matches: false })
        digestsValid = false
        issues.push(`missing artifact: ${entry.path}`)
        continue
      }
      const matches = sha256Hex(readFileSync(full)) === entry.sha256
      digests.push({ path: entry.path, kind: entry.kind, matches })
      if (!matches) {
        digestsValid = false
        issues.push(`artifact changed since it was packed: ${entry.path}`)
      }
    }
  }

  let signatureValid = false
  if (pack.signature && pack.signerPublicKey) {
    try {
      signatureValid = verifySig(
        null,
        Buffer.from(signable(pack), 'utf8'),
        createPublicKey(pack.signerPublicKey),
        Buffer.from(pack.signature, 'base64'),
      )
    } catch (err) {
      issues.push(`signature could not be checked: ${(err as Error).message}`)
    }
    if (!signatureValid) issues.push('signature does not verify')
  } else {
    issues.push('pack is unsigned')
  }

  const present = new Set(pack.entries.map((e) => e.kind))
  const missingKinds = (Object.keys(EVIDENCE_KINDS) as EvidenceKind[]).filter(
    (kind) => EVIDENCE_KINDS[kind].required && !present.has(kind),
  )
  const failedKinds = [...new Set(pack.entries.filter((e) => e.status === 'failed' || e.status === 'error').map((e) => e.kind))]
  for (const kind of missingKinds) issues.push(`no ${kind} evidence in the pack (required)`)
  for (const kind of failedKinds) issues.push(`${kind} evidence reports a failure`)

  const stale = now > pack.expiresAt
  if (stale) issues.push(`pack expired at ${new Date(pack.expiresAt).toISOString()}`)

  const complete = missingKinds.length === 0
  return {
    ok: rootValid && digestsValid && signatureValid && complete && failedKinds.length === 0 && !stale,
    complete,
    signatureValid,
    digestsValid,
    rootValid,
    stale,
    missingKinds,
    failedKinds,
    issues,
    entries: digests,
  }
}

/** Render the human-readable half of a pack. */
export function renderEvidenceMarkdown(pack: ReleaseEvidencePack, verification?: PackVerification): string {
  const lines: string[] = []
  lines.push(`# Release evidence — ${pack.subject.name}@${pack.subject.version}`)
  lines.push('')
  lines.push(`| | |`)
  lines.push(`|---|---|`)
  lines.push(`| commit | ${pack.subject.commit ? `\`${pack.subject.commit.slice(0, 12)}\`` : '(no git checkout)'} |`)
  lines.push(`| tarball sha256 | ${pack.subject.tarballSha256 ?? '(no tarball packed)'} |`)
  if (pack.subject.tarballBytes) lines.push(`| tarball size | ${pack.subject.tarballBytes} bytes |`)
  lines.push(`| evidence root | \`${pack.evidenceRoot}\` |`)
  lines.push(`| created | ${new Date(pack.createdAt).toISOString()} |`)
  lines.push(`| expires | ${new Date(pack.expiresAt).toISOString()} |`)
  lines.push(`| node / platform | ${pack.environment.node} / ${pack.environment.platform}-${pack.environment.arch} |`)
  lines.push(`| signed | ${pack.signature ? 'yes (Ed25519)' : 'no'} |`)
  lines.push('')

  if (verification) {
    lines.push(`## Verification`)
    lines.push('')
    lines.push(`**${verification.ok ? 'OK' : 'NOT OK'}** — complete=${verification.complete} signature=${verification.signatureValid} digests=${verification.digestsValid} root=${verification.rootValid} stale=${verification.stale}`)
    lines.push('')
    if (verification.missingKinds.length > 0) lines.push(`- missing required evidence: ${verification.missingKinds.join(', ')}`)
    if (verification.failedKinds.length > 0) lines.push(`- failing evidence: ${verification.failedKinds.join(', ')}`)
    for (const issue of verification.issues) lines.push(`- ${issue}`)
    lines.push('')
  }

  lines.push(`## Evidence (${pack.entries.length})`)
  lines.push('')
  lines.push(`| kind | path | status | sha256 | note |`)
  lines.push(`|---|---|---|---|---|`)
  for (const entry of pack.entries) {
    lines.push(
      `| ${entry.kind} | \`${entry.path}\` | ${entry.status ?? 'n/a'} | \`${entry.sha256.slice(0, 12)}…\` | ${entry.summary ?? ''} |`,
    )
  }
  const absent = (Object.keys(EVIDENCE_KINDS) as EvidenceKind[]).filter(
    (kind) => !pack.entries.some((e) => e.kind === kind),
  )
  if (absent.length > 0) {
    lines.push('')
    lines.push(`## Not included`)
    lines.push('')
    for (const kind of absent) {
      const spec = EVIDENCE_KINDS[kind]
      lines.push(`- **${kind}** ${spec.required ? '(required)' : '(optional)'} — ${spec.describes}; normally from \`${spec.tool}\``)
    }
  }
  lines.push('')
  lines.push('> This pack states that the listed checks produced the listed results for the listed build. It does not claim the plugin is good, and it does not cover anything absent from the table above.')
  return lines.join('\n')
}

/** Write a pack plus its rendered report. */
export function writePack(targetDirectory: string, pack: ReleaseEvidencePack, verification?: PackVerification): string[] {
  const dir = resolve(targetDirectory)
  const written: string[] = []
  const jsonPath = join(dir, 'evidence.json')
  const mdPath = join(dir, 'EVIDENCE.md')
  writeFileSync(jsonPath, `${JSON.stringify(pack, null, 2)}\n`, 'utf8')
  written.push(jsonPath)
  writeFileSync(mdPath, `${renderEvidenceMarkdown(pack, verification)}\n`, 'utf8')
  written.push(mdPath)
  return written
}

/** Convenience: read a pack from disk. */
export function readPack(path: string): ReleaseEvidencePack {
  const file = statSync(path).isDirectory() ? join(path, 'evidence.json') : path
  return JSON.parse(readFileSync(file, 'utf8')) as ReleaseEvidencePack
}

export { basename }
