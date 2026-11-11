import type {
  DependencyItem,
  ParsedManifest,
  UnsupportedDependency,
  UnsupportedReason,
} from '@/types/vulnerability'

const SEMVER_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

const PACKAGE_NAME_PATTERN = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i

const LOWER_BOUND_PREFIX = /^(?:\s*(?:>=|~|\^|=|v))+\s*/i

const WILDCARD_VERSIONS = new Set(['', '*', 'x', 'X'])

const RANGE_OPERATOR_PATTERN = /[<>|]|\s/

const TAG_PATTERN = /^[a-z][a-z0-9._-]*$/i

const PARTIAL_VERSION_PATTERN = /^(?:[\dx*]+)(?:\.[\dx*]+){0,2}$/i

const MAX_PACKAGE_NAME_LENGTH = 214

const REASON_NOTES: Record<UnsupportedReason, string> = {
  git: 'Git repository reference — OSV checks require an npm registry version.',
  url: 'Remote tarball URL — OSV checks require an npm registry version.',
  file: 'Local path or GitHub shorthand — OSV checks require an npm registry version.',
  workspace: 'Workspace protocol — the version is resolved locally by the package manager.',
  link: 'Symlink protocol (link:) — the version is resolved locally by the package manager.',
  alias: 'npm: alias without a usable target package and version.',
  tag: 'Dist-tag — resolves to different versions over time, so it cannot be checked reliably.',
  range: 'Version range or partial version — an exact version is required for an OSV check.',
  'invalid-version': 'Version is not valid semver and cannot be checked safely.',
  'invalid-name': 'Package name is not a valid npm package name.',
}

type VersionOutcome =
  | { kind: 'version'; version: string }
  | { kind: 'unsupported'; reason: UnsupportedReason }

type EntryOutcome =
  | { item: DependencyItem; unsupported?: undefined }
  | { item?: undefined; unsupported: UnsupportedDependency }

function makeUnsupported(
  name: string,
  rawVersion: unknown,
  reason: UnsupportedReason,
): UnsupportedDependency {
  return {
    name,
    rawVersion: typeof rawVersion === 'string' ? rawVersion : String(rawVersion),
    reason,
    note: REASON_NOTES[reason],
  }
}

function makeDependency(name: string, version: string, dev: boolean): DependencyItem {
  return dev ? { name, version, ecosystem: 'npm', dev: true } : { name, version, ecosystem: 'npm' }
}

function isValidPackageName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= MAX_PACKAGE_NAME_LENGTH &&
    PACKAGE_NAME_PATTERN.test(name)
  )
}

function normalizeVersion(version: string): string | null {
  const cleaned = version.replace(LOWER_BOUND_PREFIX, '').trim()
  return SEMVER_PATTERN.test(cleaned) ? cleaned : null
}

function classifyVersion(version: string): VersionOutcome {
  if (WILDCARD_VERSIONS.has(version)) {
    return { kind: 'unsupported', reason: 'range' }
  }
  if (version.startsWith('workspace:')) {
    return { kind: 'unsupported', reason: 'workspace' }
  }
  if (version.startsWith('link:')) {
    return { kind: 'unsupported', reason: 'link' }
  }
  if (version.startsWith('file:') || version.startsWith('.') || version.startsWith('/')) {
    return { kind: 'unsupported', reason: 'file' }
  }
  if (/^git/i.test(version) || /^(github|bitbucket|gist):/i.test(version)) {
    return { kind: 'unsupported', reason: 'git' }
  }
  if (/^https?:\/\//i.test(version)) {
    return { kind: 'unsupported', reason: 'url' }
  }
  if (version.includes('/')) {
    return { kind: 'unsupported', reason: 'file' }
  }

  const normalized = normalizeVersion(version)
  if (normalized !== null) {
    return { kind: 'version', version: normalized }
  }

  if (RANGE_OPERATOR_PATTERN.test(version)) {
    return { kind: 'unsupported', reason: 'range' }
  }
  if (TAG_PATTERN.test(version)) {
    return { kind: 'unsupported', reason: 'tag' }
  }
  if (PARTIAL_VERSION_PATTERN.test(version)) {
    return { kind: 'unsupported', reason: 'range' }
  }
  return { kind: 'unsupported', reason: 'invalid-version' }
}

function resolveAlias(
  name: string,
  rawVersion: string,
  trimmed: string,
  dev: boolean,
): EntryOutcome {
  const target = trimmed.slice('npm:'.length)
  const separator = target.lastIndexOf('@')

  if (separator <= 0) {
    return { unsupported: makeUnsupported(name, rawVersion, 'alias') }
  }

  const targetName = target.slice(0, separator)
  const versionSpec = target.slice(separator + 1)

  if (!isValidPackageName(targetName)) {
    return { unsupported: makeUnsupported(name, rawVersion, 'alias') }
  }

  const outcome = classifyVersion(versionSpec)
  if (outcome.kind === 'unsupported') {
    const reason = outcome.reason === 'invalid-name' ? 'alias' : outcome.reason
    return { unsupported: makeUnsupported(name, rawVersion, reason) }
  }

  return { item: makeDependency(targetName, outcome.version, dev) }
}

function resolveEntry(name: string, value: unknown, dev: boolean): EntryOutcome {
  if (!isValidPackageName(name)) {
    return { unsupported: makeUnsupported(name, value, 'invalid-name') }
  }
  if (typeof value !== 'string') {
    return { unsupported: makeUnsupported(name, value, 'invalid-version') }
  }

  const trimmed = value.trim()
  if (trimmed.startsWith('npm:')) {
    return resolveAlias(name, value, trimmed, dev)
  }

  const outcome = classifyVersion(trimmed)
  if (outcome.kind === 'unsupported') {
    return { unsupported: makeUnsupported(name, value, outcome.reason) }
  }

  return { item: makeDependency(name, outcome.version, dev) }
}

export function parsePackageJson(content: string): ParsedManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'unparseable content'
    throw new Error(`Invalid JSON: ${detail}`)
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Invalid manifest: expected a JSON object at the root.')
  }

  const root = parsed as Record<string, unknown>
  const manifest: ParsedManifest = { dependencies: [], unsupported: [], warnings: [] }
  const seenDependencies = new Set<string>()
  const seenUnsupported = new Set<string>()

  const extract = (section: 'dependencies' | 'devDependencies', dev: boolean) => {
    const record = root[section]
    if (record === undefined || record === null) return
    if (typeof record !== 'object' || Array.isArray(record)) {
      manifest.warnings.push(`"${section}" is not an object and was skipped.`)
      return
    }

    for (const [name, value] of Object.entries(record as Record<string, unknown>)) {
      const outcome = resolveEntry(name, value, dev)

      if (outcome.unsupported) {
        const key = `${outcome.unsupported.name}|${outcome.unsupported.rawVersion}|${outcome.unsupported.reason}`
        if (!seenUnsupported.has(key)) {
          seenUnsupported.add(key)
          manifest.unsupported.push(outcome.unsupported)
        }
        continue
      }

      const dependency = outcome.item
      const key = `${dependency.name}@${dependency.version}`
      if (!seenDependencies.has(key)) {
        seenDependencies.add(key)
        manifest.dependencies.push(dependency)
      }
    }
  }

  extract('dependencies', false)
  extract('devDependencies', true)

  return manifest
}
