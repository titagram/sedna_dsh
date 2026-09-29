// Build-time gate: every bundle the `web` profile names must be able to resolve every
// dependency it declares.
//
// This exists because the failure it catches is silent. Without it the build succeeds, the
// image ships, and DSH dies at *boot* with "plugin(s) failed to load:
// @deepseek-ai/dsh-sandbox-local" -- a message that says nothing about npm having skipped an
// unpublished prerelease. Failing here names the missing package and the parent that wanted it.
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'

const bundles = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']
const missing = []

for (const bundle of bundles) {
  const require_ = createRequire(import.meta.url)
  let entry
  try {
    entry = require_.resolve(`${bundle}/package.json`)
  } catch {
    missing.push(`${bundle} itself is not installed`)
    continue
  }
  const pkg = JSON.parse(readFileSync(entry, 'utf8'))
  const scope = createRequire(entry)
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    // Resolve the bare specifier first. Asking for `${dep}/package.json` looks stricter but
    // is wrong: a package whose exports map does not include ./package.json throws for a
    // dependency that is installed and fine, which is how this check first reported commander
    // and open as missing from a tree that had both.
    try {
      scope.resolve(dep)
    } catch {
      try {
        scope.resolve(`${dep}/package.json`)
      } catch {
        missing.push(`${bundle} needs ${dep}`)
      }
    }
  }
}

if (missing.length > 0) {
  console.error('unresolvable bundle dependencies:')
  for (const line of missing) console.error(`  ${line}`)
  process.exit(1)
}
console.log(`checked ${bundles.length} bundle(s): every declared dependency resolves`)
