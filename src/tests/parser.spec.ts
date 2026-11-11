import { describe, it, expect } from 'vitest'
import { parsePackageJson } from '../utils/parser'
import type { UnsupportedReason } from '../types/vulnerability'

const stringify = (value: unknown) => JSON.stringify(value)

describe('parsePackageJson — valid manifests', () => {
  it('extracts dependencies and devDependencies with normalized versions', () => {
    const parsed = parsePackageJson(
      stringify({
        dependencies: { lodash: '^4.17.15', axios: '~0.21.1', vue: '3.4.21' },
        devDependencies: { typescript: '>=5.0.0' },
      }),
    )

    expect(parsed.unsupported).toEqual([])
    expect(parsed.warnings).toEqual([])
    expect(parsed.dependencies).toEqual([
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
      { name: 'axios', version: '0.21.1', ecosystem: 'npm' },
      { name: 'vue', version: '3.4.21', ecosystem: 'npm' },
      { name: 'typescript', version: '5.0.0', ecosystem: 'npm', dev: true },
    ])
  })

  it('normalizes =, v and >= prefixes', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { pinia: '=2.1.7', vite: 'v5.0.0', rollup: '>=4.0.0' } }),
    )
    expect(parsed.dependencies.map((dependency) => dependency.version)).toEqual([
      '2.1.7',
      '5.0.0',
      '4.0.0',
    ])
  })

  it('preserves prerelease and build metadata', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { alpha: '^1.0.0-beta.1', meta: '2.0.0+build.42' } }),
    )
    expect(parsed.dependencies.map((dependency) => dependency.version)).toEqual([
      '1.0.0-beta.1',
      '2.0.0+build.42',
    ])
  })

  it('supports scoped package names', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { '@vue/test-utils': '^2.4.0' } }),
    )
    expect(parsed.dependencies).toEqual([
      { name: '@vue/test-utils', version: '2.4.0', ecosystem: 'npm' },
    ])
  })

  it('returns empty lists when sections are missing', () => {
    const parsed = parsePackageJson(stringify({ name: 'demo' }))
    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported).toEqual([])
    expect(parsed.warnings).toEqual([])
  })

  it('returns empty lists when sections are empty objects', () => {
    const parsed = parsePackageJson(stringify({ dependencies: {}, devDependencies: {} }))
    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported).toEqual([])
  })

  it('skips malformed sections and records warnings', () => {
    const parsed = parsePackageJson(stringify({ dependencies: [], devDependencies: 'oops' }))
    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported).toEqual([])
    expect(parsed.warnings).toHaveLength(2)
  })
})

describe('parsePackageJson — invalid manifests', () => {
  it('throws a descriptive error for invalid JSON', () => {
    expect(() => parsePackageJson('{ not json')).toThrow(/Invalid JSON/)
  })

  it('throws when the root is an array', () => {
    expect(() => parsePackageJson('[]')).toThrow(/expected a JSON object/)
  })

  it('throws when the root is a string or number', () => {
    expect(() => parsePackageJson('"nope"')).toThrow(/expected a JSON object/)
    expect(() => parsePackageJson('42')).toThrow(/expected a JSON object/)
  })

  it('throws for null roots', () => {
    expect(() => parsePackageJson('null')).toThrow(/expected a JSON object/)
  })
})

describe('parsePackageJson — unsupported dependency formats', () => {
  const cases: Array<[string, UnsupportedReason]> = [
    ['git+https://github.com/user/repo.git', 'git'],
    ['git://github.com/user/repo.git', 'git'],
    ['github:user/repo', 'git'],
    ['bitbucket:user/repo', 'git'],
    ['https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz', 'url'],
    ['file:../local-pkg', 'file'],
    ['../local-pkg', 'file'],
    ['./sibling', 'file'],
    ['packages/local', 'file'],
    ['workspace:*', 'workspace'],
    ['workspace:^1.2.3', 'workspace'],
    ['link:../local-pkg', 'link'],
    ['latest', 'tag'],
    ['next', 'tag'],
    ['*', 'range'],
    ['x', 'range'],
    ['1.2', 'range'],
    ['1.x', 'range'],
    ['1.2.x', 'range'],
    ['>1.2.3', 'range'],
    ['<=2.0.0', 'range'],
    ['>=1.2.3 <2.0.0', 'range'],
    ['1.2.3 || 2.0.0', 'range'],
    ['1.2.3 - 2.3.4', 'range'],
    ['1.2.3.4', 'invalid-version'],
  ]

  it.each(cases)('flags "%s" as %s', (rawVersion, reason) => {
    const parsed = parsePackageJson(stringify({ dependencies: { pkg: rawVersion } }))

    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported).toHaveLength(1)
    expect(parsed.unsupported[0]).toMatchObject({ name: 'pkg', rawVersion, reason })
    expect(parsed.unsupported[0].note).toBeTruthy()
  })

  it('flags non-string versions as invalid-version', () => {
    const parsed = parsePackageJson(stringify({ dependencies: { pkg: 123 } }))

    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported[0]).toMatchObject({
      name: 'pkg',
      rawVersion: '123',
      reason: 'invalid-version',
    })
  })

  it('flags invalid package names', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { 'bad name': '1.2.3', '': '1.2.3' } }),
    )

    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported.map((entry) => entry.reason)).toEqual([
      'invalid-name',
      'invalid-name',
    ])
  })
})

describe('parsePackageJson — npm aliases', () => {
  it('resolves npm: aliases to the target package and version', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { 'my-lodash': 'npm:lodash@4.17.15' } }),
    )

    expect(parsed.unsupported).toEqual([])
    expect(parsed.dependencies).toEqual([
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
    ])
  })

  it('resolves scoped aliases with range prefixes', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { 'my-scoped': 'npm:@scope/pkg@^1.2.3' } }),
    )

    expect(parsed.dependencies).toEqual([
      { name: '@scope/pkg', version: '1.2.3', ecosystem: 'npm' },
    ])
  })

  it('flags aliases without a version', () => {
    const parsed = parsePackageJson(stringify({ dependencies: { alias: 'npm:lodash' } }))

    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported).toHaveLength(1)
    expect(parsed.unsupported[0].reason).toBe('alias')
  })

  it('flags aliases with unresolvable target versions', () => {
    const parsed = parsePackageJson(
      stringify({ dependencies: { alias: 'npm:lodash@latest' } }),
    )

    expect(parsed.dependencies).toEqual([])
    expect(parsed.unsupported[0].reason).toBe('tag')
  })
})

describe('parsePackageJson — duplicate handling', () => {
  it('dedupes identical entries across dependencies and devDependencies', () => {
    const parsed = parsePackageJson(
      stringify({
        dependencies: { lodash: '^4.17.21' },
        devDependencies: { lodash: '~4.17.21' },
      }),
    )

    expect(parsed.dependencies).toEqual([
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ])
  })

  it('keeps distinct versions of the same package', () => {
    const parsed = parsePackageJson(
      stringify({
        dependencies: { lodash: '^3.10.1' },
        devDependencies: { lodash: '^4.17.21' },
      }),
    )

    expect(parsed.dependencies).toEqual([
      { name: 'lodash', version: '3.10.1', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm', dev: true },
    ])
  })

  it('dedupes aliases that resolve to an existing dependency', () => {
    const parsed = parsePackageJson(
      stringify({
        dependencies: { lodash: '^4.17.21', 'alt-lodash': 'npm:lodash@^4.17.21' },
      }),
    )

    expect(parsed.dependencies).toHaveLength(1)
    expect(parsed.dependencies[0].name).toBe('lodash')
  })
})
