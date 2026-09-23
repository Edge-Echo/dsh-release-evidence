// Acceptance harness for dsh-release-evidence.
//
// Drives the real CLI over a fixture repository and checks the claims a reviewer relies
// on. Runs the compiled binary rather than the library, so argument parsing, exit codes
// and file layout are covered too.
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const cli = resolve(here, '..', 'lib', 'cli.js')

const results = []
let failed = 0
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok })
  if (!ok) failed++
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ` - ${detail}` : ''}`)
}

/** Run the CLI and capture stdout, stderr and the exit code without throwing. */
function run(args) {
  try {
    const stdout = execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
    return { code: 0, stdout }
  } catch (err) {
    return { code: err.status ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' }
  }
}

const fixture = mkdtempSync(join(tmpdir(), 'evidence-verify-'))
const run1 = join(fixture, '.dsh-testkit', 'runs', '2026-09-23T07-00-00')
mkdirSync(run1, { recursive: true })

writeFileSync(
  join(fixture, 'package.json'),
  JSON.stringify({ name: 'fixture-plugin', version: '2.0.0' }, null, 2),
  'utf8',
)
writeFileSync(
  join(run1, 'report.json'),
  JSON.stringify({
    schema: 'dsh-testkit/1',
    status: 'passed',
    dshVersion: '0.15.3',
    artifactDigest: 'sha256:deadbeef',
    stages: ['resolve', 'install', 'package', 'register', 'exercise', 'uninstall', 'reboot'].map((name) => ({ name, ok: true })),
  }),
  'utf8',
)
writeFileSync(join(run1, 'junit.xml'), '<testsuite name="lifecycle" tests="7" failures="0" errors="0" skipped="0"/>', 'utf8')
writeFileSync(join(fixture, 'eval-harness-report.json'), JSON.stringify({ status: 'passed', cases: [1, 2, 3] }), 'utf8')

try {
  console.log('1. collect')
  const collected = run(['collect', '--root', fixture])
  check('collect exits 0', collected.code === 0)
  check('recognises the testkit report', /lifecycle-test\s+\.dsh-testkit/.test(collected.stdout))
  check('reads the junit verdict', /tests=7, failures=0/.test(collected.stdout))
  check('recognises the eval report', /regression-eval/.test(collected.stdout))
  check('names the missing required evidence', /missing required: packed-artifact/.test(collected.stdout))

  console.log('\n2. unsigned pack is refused as ok')
  const unsigned = run(['pack', '--root', fixture, '--out', join(fixture, '.unsigned'), '--pack-tarball'])
  check('pack exits 0', unsigned.code === 0, `code=${unsigned.code}`)
  const unsignedVerify = run(['verify', join(fixture, '.unsigned'), '--root', fixture])
  check('unsigned pack fails verification', unsignedVerify.code === 1)
  check('and says why', /pack is unsigned/.test(unsignedVerify.stdout))

  console.log('\n3. signed pack')
  const key = join(fixture, 'key.pem')
  check('keygen exits 0', run(['keygen', '--out', key]).code === 0)
  const packed = run(['pack', '--root', fixture, '--out', join(fixture, '.dsh-evidence'), '--key', key, '--pack-tarball'])
  check('pack exits 0', packed.code === 0, `code=${packed.code}`)
  check('reports the subject', /fixture-plugin@2\.0\.0/.test(packed.stdout))
  check('reports a merkle root', /evidence root\s+:\s+[0-9a-f]{64}/.test(packed.stdout))
  check('reports completeness', /complete\s+:\s+true/.test(packed.stdout))
  check('wrote both artifacts', existsSync(join(fixture, '.dsh-evidence', 'evidence.json')) && existsSync(join(fixture, '.dsh-evidence', 'EVIDENCE.md')))

  const verified = run(['verify', join(fixture, '.dsh-evidence'), '--root', fixture, '--require-complete'])
  check('signed complete pack verifies', verified.code === 0, verified.stdout.trim().split('\n').pop())
  check('all four checks pass', /complete=true signature=true digests=true root=true stale=false/.test(verified.stdout))

  console.log('\n4. tampering is caught')
  writeFileSync(join(run1, 'junit.xml'), '<testsuite name="lifecycle" tests="7" failures="3" errors="0"/>', 'utf8')
  const tampered = run(['verify', join(fixture, '.dsh-evidence'), '--root', fixture, '--require-complete'])
  check('edited report fails verification', tampered.code === 1)
  check('and is named', /artifact changed since it was packed/.test(tampered.stdout))

  console.log('\n5. the report renders what was checked and what was not')
  const md = readFileSync(join(fixture, '.dsh-evidence', 'EVIDENCE.md'), 'utf8')
  check('names the subject', /fixture-plugin@2\.0\.0/.test(md))
  check('lists the artifacts', /## Evidence \(\d+\)/.test(md))
  check('lists what is absent', /## Not included/.test(md))
  check('states the limits of the claim', /does not claim the plugin is good/.test(md))

  console.log('\n6. usage errors')
  check('unknown command exits 2', run(['nonsense']).code === 2)
  check('packing a repo with no evidence exits 3', run(['pack', '--root', mkdtempSync(join(tmpdir(), 'empty-'))]).code === 3)
} finally {
  rmSync(fixture, { recursive: true, force: true })
}

console.log(`\n${results.length - failed}/${results.length} checks passed`)
if (failed > 0) {
  for (const r of results.filter((x) => !x.ok)) console.log(`  failed: ${r.name}`)
  process.exit(1)
}
void cpSync
