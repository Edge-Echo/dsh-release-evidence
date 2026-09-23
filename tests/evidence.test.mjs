// Tests for the release-evidence pack.
//
// The claims worth testing are the ones a reviewer relies on: that a report swapped
// after packing is detected, that a missing required artifact makes the pack
// incomplete rather than "ok", that a failing report fails the pack, and that the
// signature covers the subject and the entries.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  EVIDENCE_SCHEMA,
  collect,
  evidenceRoot,
  readSubject,
  renderEvidenceMarkdown,
  signPack,
  verifyPack,
  writePack,
} from '../lib/evidence.js'

const KEY = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

/** A throwaway repository containing whatever evidence the test needs. */
function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'evidence-'))
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content, 'utf8')
  }
  return dir
}

const baseRepo = (over = {}) => ({
  'package.json': JSON.stringify({ name: 'demo-plugin', version: '1.2.3' }),
  // The packed artifact is required evidence: testkit's own docs call "compiles and
  // passes unit tests but the tarball is missing files" a real release failure.
  'demo-plugin-1.2.3.tgz': 'tarball bytes',
  '.dsh-testkit/runs/2026-09-23T00-00-00/report.json': JSON.stringify({
    status: 'passed',
    stages: ['resolve', 'install', 'package', 'register', 'exercise', 'uninstall', 'reboot'],
    artifactDigest: 'sha256:abc',
  }),
  '.dsh-testkit/runs/2026-09-23T00-00-00/junit.xml': '<testsuite tests="7" failures="0"/>',
  ...over,
})

function buildPack(root, opts = {}) {
  const { entries } = collect({ root })
  const now = Date.now()
  const tarball = 'tarball' in opts ? opts.tarball : join(root, 'demo-plugin-1.2.3.tgz')
  const pack = {
    schema: EVIDENCE_SCHEMA,
    subject: readSubject(root, tarball),
    entries,
    evidenceRoot: evidenceRoot(entries),
    createdAt: now,
    expiresAt: now + 86400000,
    environment: { node: process.version, platform: process.platform, arch: process.arch },
  }
  return opts.sign ? signPack(pack, KEY) : pack
}

test('collection classifies known evidence and reads its verdict', () => {
  const root = fixture(baseRepo())
  try {
    const { entries } = collect({ root })
    const kinds = entries.map((e) => e.kind)
    assert.ok(kinds.includes('lifecycle-test'), 'testkit reports must be recognised')
    assert.equal(entries.length, 3, `expected 3 artifacts, got ${entries.length}`)

    const report = entries.find((e) => e.path.endsWith('report.json'))
    assert.equal(report.status, 'passed')
    assert.equal(report.producedBy, 'dsh-testkit')
    assert.match(report.summary ?? '', /7 stages/)
    assert.equal(report.sha256.length, 64)

    const junit = entries.find((e) => e.path.endsWith('junit.xml'))
    assert.equal(junit.kind, 'lifecycle-test')
    assert.equal(junit.status, 'passed')

    // Paths are repository-relative so the pack stays portable.
    for (const entry of entries) assert.ok(!entry.path.includes(':\\') && !entry.path.startsWith('/'), entry.path)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('stale artifacts are skipped with a stated reason', () => {
  const root = fixture(baseRepo())
  try {
    // "Now" is set 30 days ahead of the freshly written files, so the age is
    // deterministic instead of depending on timestamp granularity.
    const { entries, skipped } = collect({ root, now: Date.now() + 30 * 86400000, maxAgeMs: 14 * 86400000 })
    assert.equal(entries.length, 0)
    assert.equal(skipped.length, 3)
    assert.match(skipped[0], /older than/)
    // And the same artifacts are collected when the window covers them.
    assert.equal(collect({ root, now: Date.now() + 30 * 86400000, maxAgeMs: 60 * 86400000 }).entries.length, 3)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a clean signed pack verifies', () => {
  const root = fixture(baseRepo())
  try {
    const pack = buildPack(root, { sign: true })
    const v = verifyPack(pack, root)
    assert.equal(v.signatureValid, true)
    assert.equal(v.digestsValid, true)
    assert.equal(v.rootValid, true)
    assert.equal(v.complete, true, `missing: ${v.missingKinds.join(', ')}`)
    assert.equal(v.ok, true, v.issues.join('; '))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a report edited after packing is detected', () => {
  const root = fixture(baseRepo())
  try {
    const pack = buildPack(root, { sign: true })
    assert.equal(verifyPack(pack, root).ok, true)

    // Flip a failure count in place — the same edit an author would make to hide one.
    const junit = join(root, '.dsh-testkit/runs/2026-09-23T00-00-00/junit.xml')
    writeFileSync(junit, '<testsuite tests="7" failures="0" note="edited"/>', 'utf8')

    const v = verifyPack(pack, root)
    assert.equal(v.digestsValid, false)
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /artifact changed since it was packed/.test(i)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('adding or removing an entry breaks the evidence root', () => {
  const root = fixture(baseRepo())
  try {
    const pack = buildPack(root, { sign: true })
    const withExtra = [...pack.entries, { kind: 'security-audit', path: 'audit.json', sha256: 'f'.repeat(64), bytes: 1 }]
    const v = verifyPack({ ...pack, entries: withExtra }, root)
    assert.equal(v.rootValid, false)
    assert.equal(v.ok, false)

    const reordered = [...pack.entries].reverse()
    assert.notEqual(evidenceRoot(reordered), pack.evidenceRoot, 'entry order must be covered')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('the signature covers the subject, so rewriting it is detected', () => {
  const root = fixture(baseRepo())
  try {
    const pack = buildPack(root, { sign: true })
    const lying = { ...pack, subject: { ...pack.subject, version: '9.9.9' } }
    const v = verifyPack(lying, root)
    assert.equal(v.signatureValid, false)
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /signature does not verify/.test(i)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('an unsigned pack is not reported as ok', () => {
  const root = fixture(baseRepo())
  try {
    const v = verifyPack(buildPack(root), root)
    assert.equal(v.signatureValid, false)
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /unsigned/.test(i)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('missing required evidence makes the pack incomplete, not ok', () => {
  const root = fixture({
    'package.json': JSON.stringify({ name: 'demo-plugin', version: '1.2.3' }),
    'evidence/compat.json': JSON.stringify({ status: 'passed' }),
  })
  try {
    const pack = buildPack(root, { sign: true })
    const v = verifyPack(pack, root)
    assert.equal(v.complete, false)
    assert.deepEqual(v.missingKinds.sort(), ['lifecycle-test', 'packed-artifact'])
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /no lifecycle-test evidence/.test(i)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a failing report fails the pack even when everything else is present', () => {
  const root = fixture(
    baseRepo({
      '.dsh-testkit/runs/2026-09-23T00-00-00/report.json': JSON.stringify({ status: 'failed', stages: ['resolve', 'install'] }),
      'demo-plugin-1.2.3.tgz': 'not really a tarball',
    }),
  )
  try {
    const pack = buildPack(root, { tarball: join(root, 'demo-plugin-1.2.3.tgz'), sign: true })
    const v = verifyPack(pack, root)
    assert.equal(v.complete, true)
    assert.deepEqual(v.failedKinds, ['lifecycle-test'])
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /lifecycle-test evidence reports a failure/.test(i)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('an expired pack is reported stale', () => {
  const root = fixture(baseRepo({ 'demo-plugin-1.2.3.tgz': 'bytes' }))
  try {
    const pack = buildPack(root, { tarball: join(root, 'demo-plugin-1.2.3.tgz'), sign: true })
    const later = pack.expiresAt + 1000
    const v = verifyPack(pack, root, later)
    assert.equal(v.stale, true)
    assert.equal(v.ok, false)
    assert.ok(v.issues.some((i) => /expired at/.test(i)))
    // The same pack verifies before its expiry, so staleness is the only difference.
    assert.equal(verifyPack(pack, root, pack.createdAt).ok, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a packed tarball is recorded by digest', () => {
  const root = fixture(baseRepo({ 'demo-plugin-1.2.3.tgz': 'tarball bytes' }))
  try {
    const pack = buildPack(root, { tarball: join(root, 'demo-plugin-1.2.3.tgz'), sign: true })
    assert.equal(pack.subject.tarballBytes, 13)
    assert.equal(pack.subject.tarballSha256?.length, 64)
    assert.ok(pack.entries.some((e) => e.kind === 'packed-artifact'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('the written pack round-trips through disk and renders', () => {
  const root = fixture(baseRepo())
  const out = mkdtempSync(join(tmpdir(), 'evidence-out-'))
  try {
    const pack = buildPack(root, { sign: true })
    const files = writePack(out, pack, verifyPack(pack, root))
    assert.equal(files.length, 2)
    const reloaded = JSON.parse(readFileSync(join(out, 'evidence.json'), 'utf8')) 
    assert.equal(verifyPack(reloaded, root).ok, true, 'a pack must survive serialisation unchanged')

    const md = renderEvidenceMarkdown(reloaded, verifyPack(reloaded, root))
    assert.match(md, /Release evidence — demo-plugin@1\.2\.3/)
    assert.match(md, /signed \| yes \(Ed25519\)/)
    assert.match(md, /## Evidence \(3\)/)
    // Absent kinds are listed, so a reader sees what was not checked.
    assert.match(md, /regression-eval/)
  } finally {
    rmSync(root, { recursive: true, force: true })
    rmSync(out, { recursive: true, force: true })
  }
})

test('entries cannot be replayed across packs', () => {
  // Two packs of different builds must not share an evidence root when their
  // artifacts differ, or a pack for a passing build could be presented with another's.
  const rootA = fixture(baseRepo())
  const rootB = fixture(baseRepo({ '.dsh-testkit/runs/2026-09-23T00-00-00/junit.xml': '<testsuite tests="7" failures="1"/>' }))
  try {
    const a = buildPack(rootA, { sign: true })
    const b = buildPack(rootB, { sign: true })
    assert.notEqual(a.evidenceRoot, b.evidenceRoot)
    // And a pack's own entries cannot verify against the other's root.
    const swapped = a.entries
    assert.notEqual(evidenceRoot(swapped), b.evidenceRoot)
  } finally {
    rmSync(rootA, { recursive: true, force: true })
    rmSync(rootB, { recursive: true, force: true })
  }
})
