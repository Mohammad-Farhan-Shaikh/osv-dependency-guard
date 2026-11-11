import type {
  ScanMetrics,
  ScannedResult,
  SeverityLevel,
  VulnerabilityAdvisory,
} from '@/types/vulnerability'

export function makeAdvisory(
  overrides: Partial<VulnerabilityAdvisory> = {},
): VulnerabilityAdvisory {
  return {
    id: 'GHSA-test-1234',
    summary: 'Prototype pollution in lodash',
    details: 'Details line one.\nDetails line two.',
    aliases: ['CVE-2021-23337'],
    severity: 'HIGH',
    fixedVersion: '4.17.21',
    fixedVersions: ['4.17.21'],
    affectedRanges: [{ type: 'SEMVER', introduced: '0', fixed: '4.17.21' }],
    references: [{ type: 'ADVISORY', url: 'https://example.com/adv' }],
    published: '2021-01-01T00:00:00Z',
    modified: '2021-02-01T00:00:00Z',
    ...overrides,
  }
}

export function makeVulnerableResult(
  name = 'lodash',
  version = '4.17.15',
  severity: SeverityLevel = 'HIGH',
): ScannedResult {
  return {
    dependency: { name, version, ecosystem: 'npm' },
    isVulnerable: true,
    advisories: [makeAdvisory({ severity })],
    status: 'vulnerable',
  }
}

export function makeCleanResult(name = 'vue', version = '3.5.0', dev = false): ScannedResult {
  return {
    dependency: { name, version, ecosystem: 'npm', dev },
    isVulnerable: false,
    advisories: [],
    status: 'clean',
  }
}

export function makeFailedResult(
  name = 'express',
  version = '4.18.0',
  error = 'Network error',
): ScannedResult {
  return {
    dependency: { name, version, ecosystem: 'npm' },
    isVulnerable: false,
    advisories: [],
    status: 'error',
    error,
  }
}

export function makeMetrics(overrides: Partial<ScanMetrics> = {}): ScanMetrics {
  return {
    total: 0,
    vulnerableCount: 0,
    cleanCount: 0,
    errorCount: 0,
    pendingCount: 0,
    healthScore: 100,
    isComplete: true,
    ...overrides,
  }
}
