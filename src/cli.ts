#!/usr/bin/env node
// dsh-release-evidence CLI.
//
//   dsh-evidence collect [--root .]                  show what evidence would be picked up
//   dsh-evidence pack    [--root .] [--out dir] [--key k.pem] [--expires-days 30]
//   dsh-evidence verify  <dir|evidence.json> [--root .] [--require-complete]
//   dsh-evidence keygen  [--out key.pem]
//
// Exit codes: 0 ok, 1 verification failed, 2 usage error, 3 the pack could not be built.
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { createPrivateKey, generateKeyPairSync } from 'node:crypto'
import { join, resolve } from 'node:path'

import {
  EVIDENCE_KINDS,
  EVIDENCE_SCHEMA,
  collect,
  evidenceRoot,
  readPack,
  readSubject,
  renderEvidenceMarkdown,
  signPack,
  verifyPack,
  writePack,
  type EvidenceKind,
  type ReleaseEvidencePack,
} from './evidence.js'

const USAGE = `dsh-release-evidence — one verifiable pack per release

usage:
  dsh-evidence collect [--root <dir>] [--json]
  dsh-evidence pack    [--root <dir>] [--out <dir>] [--key <key.pem>]
                       [--expires-days <n>] [--pack-tarball] [--max-age-days <n>]
  dsh-evidence verify  <dir|evidence.json> [--root <dir>] [--require-complete] [--json]
  dsh-evidence keygen  [--out <key.pem>]

Evidence kinds and where they are found automatically:
${(Object.keys(EVIDENCE_KINDS) as EvidenceKind[])
  .map((k) => `  ${k.padEnd(17)} ${EVIDENCE_KINDS[k].required ? 'required' : 'optional'}  ${EVIDENCE_KINDS[k].describes}`)
  .join('\n')}
`

interface Args {
  command: string
  positional: string[]
  flags: Map<string, string | true>
}

function parseArgs(argv: string[]): Args {
  const [command = '', ...rest] = argv
  const positional: string[] = []
  const flags = new Map<string, string | true>()
  const isFlag = (t: string): boolean => t.length > 1 && t.startsWith('-')
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!
    if (isFlag(token)) {
      const key = token.replace(/^-+/, '')
      const next = rest[i + 1]
      if (next !== undefined && !isFlag(next)) {
        flags.set(key, next)
        i++
      } else {
        flags.set(key, true)
      }
    } else positional.push(token)
  }
  return { command, positional, flags }
}

const flag = (a: Args, name: string): string | undefined => {
  const v = a.flags.get(name)
  return typeof v === 'string' ? v : undefined
}
const die = (msg: string, code = 2): never => {
  process.stderr.write(`error: ${msg}\n`)
  process.exit(code)
}

/**
 * Run `npm pack` and return the tarball it wrote.
 *
 * `shell: true` on Windows is deliberate, and the DEP0190 deprecation warning it
 * raises is accepted rather than silenced. The alternatives were both tried and both
 * fail: `execFileSync('npm.cmd', …)` is EINVAL (Node cannot spawn a batch file
 * directly) and `execFileSync('npm', …)` is ENOENT. Routing through
 * `cmd.exe /d /s /c` fails too, because `/s` re-writes the quoting and this machine's
 * npm lives under a path containing a space. The only user-influenced part is the
 * destination, which is quoted.
 */
function packTarball(root: string): string | undefined {
  try {
    const out = execFileSync('npm', ['pack', '--silent', '--pack-destination', `"${root}"`], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      shell: true,
    }).trim()
    const file = out.split(/\r?\n/).filter(Boolean).pop()
    return file ? join(root, file.replace(/^.*[\\/]/, '').replace(/"/g, '')) : undefined
  } catch {
    return undefined
  }
}

function collectOptions(args: Args) {
  const root = resolve(flag(args, 'root') ?? '.')
  const maxAgeDays = Number(flag(args, 'max-age-days') ?? '14')
  if (!Number.isFinite(maxAgeDays) || maxAgeDays <= 0) die('--max-age-days must be a positive number')
  return { root, maxAgeMs: maxAgeDays * 86400000 }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))
  const json = args.flags.has('json')

  switch (args.command) {
    case 'collect': {
      const { root, maxAgeMs } = collectOptions(args)
      const { entries, scanned, skipped } = collect({ root, maxAgeMs })
      if (json) {
        process.stdout.write(`${JSON.stringify({ root, scanned, entries, skipped }, null, 2)}\n`)
        return
      }
      process.stdout.write(`${root}\n  scanned ${scanned} file(s)\n`)
      if (entries.length === 0) {
        process.stdout.write('  no evidence found\n')
      }
      for (const entry of entries) {
        process.stdout.write(
          `  ${entry.kind.padEnd(17)} ${entry.path}  ${entry.status ?? ''} ${entry.summary ? `(${entry.summary})` : ''}\n`,
        )
      }
      for (const note of skipped) process.stdout.write(`  skipped ${note}\n`)
      const missing = (Object.keys(EVIDENCE_KINDS) as EvidenceKind[]).filter(
        (kind) => EVIDENCE_KINDS[kind].required && !entries.some((e) => e.kind === kind),
      )
      if (missing.length > 0) process.stdout.write(`  missing required: ${missing.join(', ')}\n`)
      return
    }

    case 'pack': {
      const { root, maxAgeMs } = collectOptions(args)
      const out = resolve(flag(args, 'out') ?? join(root, '.dsh-evidence'))
      const expiresDays = Number(flag(args, 'expires-days') ?? '30')
      if (!Number.isFinite(expiresDays) || expiresDays <= 0) die('--expires-days must be a positive number')

      let tarballPath: string | undefined
      if (args.flags.has('pack-tarball')) {
        tarballPath = packTarball(root)
        if (!tarballPath) process.stderr.write('warning: npm pack failed, continuing without a tarball digest\n')
      }

      const { entries, scanned } = collect({ root, maxAgeMs })
      if (entries.length === 0) die(`no evidence found under ${root}; run the release gates first`, 3)

      const subject = readSubject(root, tarballPath)
      const now = Date.now()
      const pack: ReleaseEvidencePack = {
        schema: EVIDENCE_SCHEMA,
        subject,
        entries,
        evidenceRoot: evidenceRoot(entries),
        createdAt: now,
        expiresAt: now + expiresDays * 86400000,
        environment: {
          node: process.version,
          platform: process.platform,
          arch: process.arch,
          dshVersions: [...new Set(entries.map((e) => /dsh@?([\d.]+)/.exec(e.summary ?? '')?.[1]).filter(Boolean))] as string[],
        },
      }

      const keyPath = flag(args, 'key')
      let signed = pack
      if (keyPath) {
        signed = signPack(pack, readFileSync(resolve(keyPath), 'utf8'))
        // Refuse to ship a pack that claims to be signed when it is not.
        const check = verifyPack(signed, root)
        if (!check.signatureValid) die('the signature did not verify after signing; refusing to write the pack', 3)
      }

      mkdirSync(out, { recursive: true })
      const written = writePack(out, signed, verifyPack(signed, root))
      const verification = verifyPack(signed, root)
      process.stdout.write(`packed ${entries.length} artifact(s) from ${scanned} scanned file(s)\n`)
      process.stdout.write(`  subject        : ${subject.name}@${subject.version}${subject.commit ? ` (${subject.commit.slice(0, 8)})` : ''}\n`)
      process.stdout.write(`  evidence root  : ${signed.evidenceRoot}\n`)
      process.stdout.write(`  signed         : ${signed.signature ? 'yes (Ed25519)' : 'no (pass --key to sign)'}\n`)
      process.stdout.write(`  complete       : ${verification.complete}${verification.missingKinds.length ? ` — missing ${verification.missingKinds.join(', ')}` : ''}\n`)
      for (const file of written) process.stdout.write(`  wrote ${file}\n`)
      if (tarballPath) rmSync(tarballPath, { force: true })
      return
    }

    case 'verify': {
      const target = args.positional[0] ?? die('verify needs a pack directory or evidence.json')
      const pack = readPack(resolve(target))
      const rootArg = flag(args, 'root')
      const root = rootArg ? resolve(rootArg) : existsSync(join(resolve(target), '..')) ? `${resolve(target)}/..` : undefined
      const verification = verifyPack(pack, root)

      if (json) {
        process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`)
      } else {
        process.stdout.write(`subject: ${pack.subject.name}@${pack.subject.version}\n`)
        process.stdout.write(`verification: ${verification.ok ? 'OK' : 'NOT OK'}\n`)
        process.stdout.write(
          `  complete=${verification.complete} signature=${verification.signatureValid} ` +
            `digests=${verification.digestsValid} root=${verification.rootValid} stale=${verification.stale}\n`,
        )
        if (pack.signature) process.stdout.write(`  signer key: ${pack.signerPublicKey?.split('\n')[1]?.slice(0, 32)}…\n`)
        for (const issue of verification.issues) process.stdout.write(`  issue: ${issue}\n`)
      }

      const requireComplete = args.flags.has('require-complete')
      const failed = requireComplete ? !verification.ok : !(verification.rootValid && verification.digestsValid && verification.signatureValid && !verification.stale)
      process.exit(failed ? 1 : 0)
    }

    case 'keygen': {
      const out = resolve(flag(args, 'out') ?? 'evidence-key.pem')
      const { privateKey } = generateKeyPairSync('ed25519')
      const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
      createPrivateKey(pem)
      const { writeFileSync } = await import('node:fs')
      writeFileSync(out, pem, { mode: 0o600 })
      process.stdout.write(`wrote ${out} (Ed25519). Keep it out of the repo; publish the public half.\n`)
      return
    }

    case '':
    case 'help':
    case '--help':
      process.stdout.write(USAGE)
      return

    default:
      process.stderr.write(`unknown command "${args.command}"\n\n${USAGE}`)
      process.exit(2)
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`fatal: ${(err as Error).message}\n`)
  process.exit(3)
})

export { renderEvidenceMarkdown }
