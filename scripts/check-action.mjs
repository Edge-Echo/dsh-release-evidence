// Validate action.yml before pushing it.
//
// The first real run of this action failed at job setup with
//   "Mapping values are not allowed in this context"
// because the header used `//` comments, which YAML does not recognise. GitHub then
// cannot load the manifest at all, so nothing in the file runs and there is no step
// output to inspect. This check catches that class of mistake locally.
import { readFileSync } from 'node:fs'

const path = process.argv[2] ?? 'action.yml'
const text = readFileSync(path, 'utf8')
const lines = text.split('\n')
const issues = []

// 1. Comment syntax: `#` only.
lines.forEach((line, i) => {
  if (/^\s*\/\//.test(line)) issues.push(`line ${i + 1}: "//" is not a YAML comment (use "#")`)
  if (/^\s*\/\*/.test(line)) issues.push(`line ${i + 1}: "/*" is not a YAML comment`)
})

// 2. Tabs are illegal for indentation.
lines.forEach((line, i) => {
  if (/^\t/.test(line)) issues.push(`line ${i + 1}: tab indentation`)
})

// 3. Action-manifest requirements. A workflow file has `on:`/`jobs:` instead, and none
//    of these apply to it, so the two are told apart rather than conflated.
const isWorkflow = /^on:/m.test(text) && /^jobs:/m.test(text)
if (!isWorkflow) {
  for (const key of ['name:', 'description:', 'runs:']) {
    if (!lines.some((l) => l.startsWith(key))) issues.push(`missing top-level "${key}"`)
  }
  if (!/^\s+using:\s*composite/m.test(text)) issues.push('runs.using must be "composite"')
}

// 4. Every `run:` step needs a shell — but only in a composite action. In a workflow
//    file the shell is optional (it defaults per platform), so requiring it there would
//    be a false positive.
const isComposite = /^\s+using:\s*composite/m.test(text)
if (isComposite) {
  const blocks = text.split(/\n(?=\s*- )/)
  for (const block of blocks) {
    if (/\brun:\s*[|>]?/.test(block) && !/shell:/.test(block)) {
      const name = /name:\s*(.+)/.exec(block)?.[1] ?? '(unnamed step)'
      issues.push(`step "${name.trim()}" has run: but no shell:`)
    }
  }
}

// 5. Inputs referenced in the body must be declared — scanning only the `inputs:` block,
//    or the `outputs:` block would be mistaken for inputs.
const inputsBlock = /^inputs:\n([\s\S]*?)^\S/m.exec(text)?.[1] ?? ''
const declared = new Set([...inputsBlock.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((m) => m[1]))
const used = new Set([...text.matchAll(/inputs\.([a-z0-9-]+)/g)].map((m) => m[1]))
for (const input of used) {
  if (!declared.has(input)) issues.push(`uses inputs.${input} but never declares it`)
}

// 6. Steps referenced by outputs must exist.
const stepIds = new Set([...text.matchAll(/^\s+id:\s*(\S+)/gm)].map((m) => m[1]))
for (const ref of text.matchAll(/steps\.([a-z0-9-]+)\.outputs/g)) {
  if (!stepIds.has(ref[1])) issues.push(`outputs reference steps.${ref[1]} but no step has that id`)
}

console.log(`${path}: ${lines.length} lines, ${declared.size} input(s), ${stepIds.size} step id(s)`)
console.log(`  inputs declared: ${[...declared].join(', ')}`)
console.log(`  inputs used    : ${[...used].join(', ')}`)
if (issues.length === 0) {
  console.log('  no issues found')
  process.exit(0)
}
console.log(`  ${issues.length} issue(s):`)
for (const issue of issues) console.log(`    - ${issue}`)
process.exit(1)
