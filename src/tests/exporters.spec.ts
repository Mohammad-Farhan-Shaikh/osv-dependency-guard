import { describe, expect, it } from 'vitest'
import type {
  ScanMetrics,
  ScannedResult,
  UnsupportedDependency,
  VulnerabilityAdvisory,
} from '@/types/vulnerability'
import {
  buildCsvReport,
  buildExportFilename,
  buildJsonReport,
  buildMarkdownReport,
  type ExportSnapshot,
} from '@/utils/exporters'

const advisory: VulnerabilityAdvisory = {
  id: 'GHSA-1',
  summary: 'Prototype pollution',
  details: 'Line one\nLine two',
  aliases: ['CVE-2021-1'],
  severity: 'HIGH',
  fixedVersion: '4.17.21',
  fixedVersions: ['4.17.21'],
  affectedRanges: [{ type: 'SEMVER', introduced: '0', fixed: '4.17.21' }],
  references: [{ type: 'ADVISORY', url: 'https://example.com/adv' }],
  published: '2021-01-01T00:00:00Z',
}

const vulnerable: ScannedResult = {
  dependency: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
  isVulnerable: true,
  advisories: [advisory],
  status: 'vulnerable',
}

const clean: ScannedResult = {
  dependency: { name: 'vue', version: '3.5.0', ecosystem: 'npm', dev: true },
  isVulnerable: false,
  advisories: [],
  status: 'clean',
}

const failed: ScannedResult = {
  dependency: { name: 'express', version: '4.18.0', ecosystem: 'npm' },
  isVulnerable: false,
  advisories: [],
  status: 'error',
  error: 'Network error',
}

const metrics: ScanMetrics = {
  total: 3,
  vulnerableCount: 1,
  cleanCount: 1,
  errorCount: 1,
  pendingCount: 0,
  healthScore: 33,
  isComplete: true,
}

const unsupported: UnsupportedDependency[] = [
  {
    name: 'foo',
    rawVersion: '>= 1 || < 2',
    reason: 'range',
    note: 'Complex range',
  },
]

const snapshot: ExportSnapshot = {
  sourceName: 'package.json',
  metrics,
  results: [vulnerable, clean, failed],
  unsupported,
  warnings: ['Ignored 1 dependency'],
  generatedAt: new Date('2026-11-11T13:45:12.345Z'),
}

describe('buildJsonReport', () => {
  it('produces valid JSON with schema metadata', () => {
    const payload = JSON.parse(buildJsonReport(snapshot))

    expect(payload.generator).toBe('DepGuard Security Engine')
    expect(payload.schemaVersion).toBe(1)
    expect(payload.generatedAt).toBe('2026-11-11T13:45:12.345Z')
    expect(payload.source).toBe('package.json')
    expect(payload.summary).toEqual(metrics)
  })

  it('includes enriched result entries', () => {
    const payload = JSON.parse(buildJsonReport(snapshot))

    expect(payload.results).toHaveLength(3)
    expect(payload.results[0]).toMatchObject({
      package: 'lodash',
      version: '4.17.15',
      type: 'prod',
      status: 'vulnerable',
      maxSeverity: 'HIGH',
      error: null,
    })
    expect(payload.results[0].advisories[0].id).toBe('GHSA-1')
    expect(payload.results[1]).toMatchObject({ package: 'vue', type: 'dev', maxSeverity: null })
    expect(payload.results[2]).toMatchObject({ package: 'express', status: 'error' })
    expect(payload.results[2].error).toBe('Network error')
  })

  it('includes unsupported dependencies and warnings', () => {
    const payload = JSON.parse(buildJsonReport(snapshot))

    expect(payload.unsupported).toEqual(unsupported)
    expect(payload.warnings).toEqual(['Ignored 1 dependency'])
  })

  it('falls back to package.json when no source name is provided', () => {
    const payload = JSON.parse(buildJsonReport({ ...snapshot, sourceName: null }))
    expect(payload.source).toBe('package.json')
  })
})

describe('buildCsvReport', () => {
  it('writes a header row and one row per dependency with CRLF endings', () => {
    const csv = buildCsvReport(snapshot)
    const lines = csv.split('\r\n').filter(Boolean)

    expect(lines[0]).toBe(
      'Package,Version,Type,Status,Severity,Advisory Count,Advisory IDs,Fixed Versions,Error',
    )
    expect(lines).toHaveLength(4)
    expect(lines[1]).toBe('lodash,4.17.15,prod,vulnerable,High,1,GHSA-1,4.17.21,')
    expect(lines[2]).toBe('vue,3.5.0,dev,clean,,0,,,')
    expect(lines[3]).toBe('express,4.18.0,prod,error,,0,,,Network error')
    expect(csv.endsWith('\r\n')).toBe(true)
  })

  it('neutralises spreadsheet formula injection', () => {
    const injected: ScannedResult = {
      dependency: { name: '=cmd|calc', version: '1.0.0', ecosystem: 'npm' },
      isVulnerable: false,
      advisories: [],
      status: 'clean',
    }

    const csv = buildCsvReport({ ...snapshot, results: [injected] })

    expect(csv).toContain("'=cmd|calc,1.0.0,prod,clean")
  })

  it('quotes values containing commas, quotes or newlines', () => {
    const messy: ScannedResult = {
      ...clean,
      status: 'error',
      error: 'bad, "quoted"\nnext line',
    }

    const csv = buildCsvReport({ ...snapshot, results: [messy] })

    expect(csv).toContain('"bad, ""quoted""\nnext line"')
  })
})

describe('buildMarkdownReport', () => {
  it('summarises the scan and lists vulnerabilities', () => {
    const markdown = buildMarkdownReport(snapshot)

    expect(markdown).toContain('# DepGuard Security Report')
    expect(markdown).toContain('- **Source:** package.json')
    expect(markdown).toContain('- **Health score:** 33/100')
    expect(markdown).toContain('| Vulnerable | 1 |')
    expect(markdown).toContain('### lodash `4.17.15` — High')
    expect(markdown).toContain('**GHSA-1** (High): Prototype pollution')
    expect(markdown).toContain('Affected: `>= 0, < 4.17.21`')
    expect(markdown).toContain('Fixed in: `4.17.21`')
    expect(markdown).toContain('Reference: https://example.com/adv')
  })

  it('lists failures, skipped dependencies and warnings', () => {
    const markdown = buildMarkdownReport(snapshot)

    expect(markdown).toContain('## Scan Failures')
    expect(markdown).toContain('`express@4.18.0`: Network error')
    expect(markdown).toContain('## Skipped Dependencies')
    expect(markdown).toContain('| foo | `>= 1 || < 2` | range |')
    expect(markdown).toContain('## Manifest Warnings')
    expect(markdown).toContain('- Ignored 1 dependency')
  })

  it('reports a clean result when nothing is vulnerable', () => {
    const markdown = buildMarkdownReport({
      ...snapshot,
      results: [clean],
      unsupported: [],
      warnings: [],
    })
    expect(markdown).toContain('No known vulnerabilities found.')
    expect(markdown).not.toContain('## Scan Failures')
    expect(markdown).not.toContain('## Skipped Dependencies')
  })
})

describe('buildExportFilename', () => {
  it('builds a slugged, timestamped filename', () => {
    const date = new Date('2026-11-11T13:45:12.345Z')
    expect(buildExportFilename('json', 'package.json', date)).toBe(
      'depguard-package-json-2026-11-11T13-45-12.json',
    )
  })

  it('falls back to package-json when no source name is given', () => {
    const date = new Date('2026-11-11T13:45:12.345Z')
    expect(buildExportFilename('csv', null, date)).toBe(
      'depguard-package-json-2026-11-11T13-45-12.csv',
    )
  })

  it('sanitises unusual source names', () => {
    const date = new Date('2026-11-11T13:45:12.345Z')
    expect(buildExportFilename('md', 'My Pkg!.json', date)).toBe(
      'depguard-my-pkg-json-2026-11-11T13-45-12.md',
    )
  })
})
