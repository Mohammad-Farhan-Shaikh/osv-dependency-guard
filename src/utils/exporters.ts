import type {
  ScanMetrics,
  ScannedResult,
  UnsupportedDependency,
} from '@/types/vulnerability'
import { SEVERITY_LABELS, getMaxSeverity } from '@/utils/severity'
import { formatAffectedRange } from '@/utils/format'

export interface ExportSnapshot {
  sourceName: string | null
  metrics: ScanMetrics
  results: ScannedResult[]
  unsupported: UnsupportedDependency[]
  warnings: string[]
  generatedAt?: Date
}

const GENERATOR_NAME = 'DepGuard Security Engine'
const SCHEMA_VERSION = 1

const CSV_HEADERS = [
  'Package',
  'Version',
  'Type',
  'Status',
  'Severity',
  'Advisory Count',
  'Advisory IDs',
  'Fixed Versions',
  'Error',
]

function resolvedDate(snapshot: ExportSnapshot): Date {
  return snapshot.generatedAt ?? new Date()
}

function collectFixedVersions(result: ScannedResult): string {
  const versions = new Set<string>()
  for (const advisory of result.advisories) {
    for (const version of advisory.fixedVersions) {
      versions.add(version)
    }
  }
  return [...versions].join('; ')
}

function resultToCsvRow(result: ScannedResult): string[] {
  const maxSeverity = getMaxSeverity(result.advisories)

  return [
    result.dependency.name,
    result.dependency.version,
    result.dependency.dev ? 'dev' : 'prod',
    result.status,
    maxSeverity ? SEVERITY_LABELS[maxSeverity] : '',
    String(result.advisories.length),
    result.advisories.map((advisory) => advisory.id).join('; '),
    collectFixedVersions(result),
    result.error ?? '',
  ]
}

function escapeCsvValue(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value
  if (/[",\r\n]/.test(guarded)) {
    return `"${guarded.replace(/"/g, '""')}"`
  }
  return guarded
}

export function buildJsonReport(snapshot: ExportSnapshot): string {
  const payload = {
    generator: GENERATOR_NAME,
    schemaVersion: SCHEMA_VERSION,
    generatedAt: resolvedDate(snapshot).toISOString(),
    source: snapshot.sourceName ?? 'package.json',
    summary: snapshot.metrics,
    results: snapshot.results.map((result) => ({
      package: result.dependency.name,
      version: result.dependency.version,
      ecosystem: result.dependency.ecosystem,
      type: result.dependency.dev ? 'dev' : 'prod',
      status: result.status,
      isVulnerable: result.isVulnerable,
      maxSeverity: getMaxSeverity(result.advisories),
      advisories: result.advisories,
      error: result.error ?? null,
    })),
    unsupported: snapshot.unsupported,
    warnings: snapshot.warnings,
  }

  return `${JSON.stringify(payload, null, 2)}\n`
}

export function buildCsvReport(snapshot: ExportSnapshot): string {
  const rows = [CSV_HEADERS, ...snapshot.results.map(resultToCsvRow)]
  const body = rows.map((row) => row.map(escapeCsvValue).join(',')).join('\r\n')
  return `${body}\r\n`
}

export function buildMarkdownReport(snapshot: ExportSnapshot): string {
  const { metrics, results, unsupported, warnings } = snapshot
  const lines: string[] = []

  lines.push('# DepGuard Security Report', '')
  lines.push(`- **Source:** ${snapshot.sourceName ?? 'package.json'}`)
  lines.push(`- **Generated:** ${resolvedDate(snapshot).toISOString()}`)
  lines.push(`- **Health score:** ${metrics.healthScore}/100`)
  lines.push('')

  lines.push('## Summary', '')
  lines.push('| Metric | Count |', '| --- | --- |')
  lines.push(`| Total scanned | ${metrics.total} |`)
  lines.push(`| Vulnerable | ${metrics.vulnerableCount} |`)
  lines.push(`| Clean | ${metrics.cleanCount} |`)
  lines.push(`| Failed | ${metrics.errorCount} |`)
  lines.push('')

  lines.push('## Vulnerabilities', '')
  const vulnerableResults = results.filter((result) => result.status === 'vulnerable')

  if (vulnerableResults.length === 0) {
    lines.push('No known vulnerabilities found.', '')
  } else {
    for (const result of vulnerableResults) {
      const maxSeverity = getMaxSeverity(result.advisories)
      const severityLabel = maxSeverity ? SEVERITY_LABELS[maxSeverity] : 'Unknown'
      lines.push(
        `### ${result.dependency.name} \`${result.dependency.version}\` — ${severityLabel}`,
        '',
      )

      for (const advisory of result.advisories) {
        lines.push(
          `- **${advisory.id}** (${SEVERITY_LABELS[advisory.severity]}): ${advisory.summary}`,
        )
        for (const range of advisory.affectedRanges) {
          lines.push(`  - Affected: \`${formatAffectedRange(range)}\``)
        }
        if (advisory.fixedVersions.length > 0) {
          lines.push(`  - Fixed in: \`${advisory.fixedVersions.join(', ')}\``)
        }
        for (const reference of advisory.references) {
          lines.push(`  - Reference: ${reference.url}`)
        }
      }
      lines.push('')
    }
  }

  const failures = results.filter((result) => result.status === 'error')
  if (failures.length > 0) {
    lines.push('## Scan Failures', '')
    for (const failure of failures) {
      lines.push(
        `- \`${failure.dependency.name}@${failure.dependency.version}\`: ${failure.error ?? 'Unknown error'}`,
      )
    }
    lines.push('')
  }

  if (unsupported.length > 0) {
    lines.push('## Skipped Dependencies', '')
    lines.push('| Package | Specified | Reason |', '| --- | --- | --- |')
    for (const item of unsupported) {
      lines.push(`| ${item.name} | \`${item.rawVersion}\` | ${item.reason} |`)
    }
    lines.push('')
  }

  if (warnings.length > 0) {
    lines.push('## Manifest Warnings', '')
    for (const warning of warnings) {
      lines.push(`- ${warning}`)
    }
    lines.push('')
  }

  return `${lines.join('\n').trimEnd()}\n`
}

export function buildExportFilename(
  extension: string,
  sourceName: string | null,
  date: Date = new Date(),
): string {
  const slug =
    (sourceName ?? 'package-json')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'scan'
  const stamp = date.toISOString().replace(/[:.]/g, '-').slice(0, 19)
  return `depguard-${slug}-${stamp}.${extension}`
}
