import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useScannerStore } from '../stores/scannerStore'
import type {
  DependencyItem,
  ScannedResult,
  VulnerabilityAdvisory,
} from '../types/vulnerability'

vi.mock('../services/osvApi', () => ({
  scanDependencies: vi.fn(),
  ScanCancelledError: class ScanCancelledError extends Error {
    constructor() {
      super('Scan cancelled')
      this.name = 'ScanCancelledError'
    }
  },
}))

import { scanDependencies } from '../services/osvApi'

const scanMock = vi.mocked(scanDependencies)

const manifest = (
  dependencies: Record<string, string>,
  devDependencies?: Record<string, string>,
) => JSON.stringify(devDependencies ? { dependencies, devDependencies } : { dependencies })

const advisory = (id = 'GHSA-test'): VulnerabilityAdvisory => ({
  id,
  summary: 'Test advisory',
  details: 'Test details',
  aliases: [],
  severity: 'HIGH',
  fixedVersions: [],
  affectedRanges: [],
  references: [],
})

const cleanResult = (dependency: DependencyItem): ScannedResult => ({
  dependency,
  isVulnerable: false,
  advisories: [],
  status: 'clean',
})

const vulnerableResult = (dependency: DependencyItem): ScannedResult => ({
  dependency,
  isVulnerable: true,
  advisories: [advisory()],
  status: 'vulnerable',
})

const errorResult = (dependency: DependencyItem): ScannedResult => ({
  dependency,
  isVulnerable: false,
  advisories: [],
  status: 'error',
  error: 'Request failed',
})

beforeEach(() => {
  setActivePinia(createPinia())
  scanMock.mockReset()
})

describe('scanner store — initial state', () => {
  it('starts idle with neutral metrics', () => {
    const store = useScannerStore()

    expect(store.isScanning).toBe(false)
    expect(store.isCancelled).toBe(false)
    expect(store.scanResults).toEqual([])
    expect(store.unsupportedDependencies).toEqual([])
    expect(store.errorMessage).toBeNull()
    expect(store.metrics.total).toBe(0)
    expect(store.metrics.healthScore).toBe(100)
    expect(store.metrics.errorCount).toBe(0)
    expect(store.isComplete).toBe(false)
    expect(store.hasFailures).toBe(false)
    expect(store.hasVulnerabilities).toBe(false)
  })
})

describe('scanner store — scanning', () => {
  it('records clean scan results and metrics', async () => {
    scanMock.mockImplementation(async (deps, options) => {
      options?.onProgress?.(deps.length, deps.length)
      return deps.map(cleanResult)
    })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ lodash: '^4.17.21', axios: '^1.6.0' }), 'package.json')

    expect(store.scanResults).toHaveLength(2)
    expect(store.isScanning).toBe(false)
    expect(store.isComplete).toBe(true)
    expect(store.metrics).toMatchObject({
      total: 2,
      cleanCount: 2,
      vulnerableCount: 0,
      errorCount: 0,
      healthScore: 100,
    })
    expect(store.sourceName).toBe('package.json')
    expect(store.lastScanAt).toBeTruthy()
    expect(store.errorMessage).toBeNull()
  })

  it('computes health score for vulnerable results', async () => {
    scanMock.mockImplementation(async (deps, options) => {
      options?.onProgress?.(deps.length, deps.length)
      return [vulnerableResult(deps[0]), cleanResult(deps[1])]
    })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ lodash: '^4.17.15', axios: '^1.6.0' }))

    expect(store.hasVulnerabilities).toBe(true)
    expect(store.metrics).toMatchObject({
      total: 2,
      vulnerableCount: 1,
      cleanCount: 1,
      healthScore: 50,
    })
  })

  it('never counts failed scans as clean and lowers the health score', async () => {
    scanMock.mockImplementation(async (deps, options) => {
      options?.onProgress?.(deps.length, deps.length)
      return [cleanResult(deps[0]), vulnerableResult(deps[1]), errorResult(deps[2])]
    })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ alpha: '1.0.0', beta: '1.0.0', gamma: '1.0.0' }))

    expect(store.metrics).toMatchObject({
      total: 3,
      cleanCount: 1,
      vulnerableCount: 1,
      errorCount: 1,
      healthScore: 33,
    })
    expect(store.hasFailures).toBe(true)
  })

  it('reports zero health when every scan fails', async () => {
    scanMock.mockImplementation(async (deps, options) => {
      options?.onProgress?.(deps.length, deps.length)
      return deps.map(errorResult)
    })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ alpha: '1.0.0', beta: '1.0.0' }))

    expect(store.metrics).toMatchObject({ cleanCount: 0, errorCount: 2, healthScore: 0 })
    expect(store.isComplete).toBe(true)
  })

  it('tracks scan progress', async () => {
    scanMock.mockImplementation(async (deps, options) => {
      options?.onProgress?.(1, deps.length)
      options?.onProgress?.(2, deps.length)
      options?.onProgress?.(deps.length, deps.length)
      return deps.map(cleanResult)
    })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ alpha: '1.0.0', beta: '1.0.0', gamma: '1.0.0' }))

    expect(store.scannedCount).toBe(3)
    expect(store.totalCount).toBe(3)
    expect(store.metrics.pendingCount).toBe(0)
  })

  it('ignores new scans while one is running', async () => {
    scanMock.mockImplementation(
      (deps, options) =>
        new Promise((resolve) => {
          options?.signal?.addEventListener('abort', () => resolve(deps.map(cleanResult)))
        }),
    )

    const store = useScannerStore()
    const first = store.scanFileContent(manifest({ alpha: '1.0.0' }))
    await store.scanFileContent(manifest({ beta: '1.0.0' }))
    store.cancelScan()
    await first

    expect(scanMock).toHaveBeenCalledTimes(1)
  })
})

describe('scanner store — manifest handling', () => {
  it('reports manifest parse errors without scanning', async () => {
    const store = useScannerStore()
    await store.scanFileContent('{ not json }')

    expect(store.errorMessage).toMatch(/Invalid JSON/)
    expect(store.scanResults).toEqual([])
    expect(store.isScanning).toBe(false)
    expect(scanMock).not.toHaveBeenCalled()
  })

  it('reports an error for manifests without dependencies', async () => {
    const store = useScannerStore()
    await store.scanFileContent(JSON.stringify({ name: 'empty' }))

    expect(store.errorMessage).toMatch(/No dependencies found/)
    expect(scanMock).not.toHaveBeenCalled()
  })

  it('reports an error when every dependency is unsupported', async () => {
    const store = useScannerStore()
    await store.scanFileContent(manifest({ repo: 'git+https://github.com/user/repo.git' }))

    expect(store.errorMessage).toMatch(/unsupported format/i)
    expect(store.unsupportedDependencies).toHaveLength(1)
    expect(scanMock).not.toHaveBeenCalled()
  })

  it('exposes unsupported dependencies but scans the rest', async () => {
    scanMock.mockImplementation(async (deps) => deps.map(cleanResult))

    const store = useScannerStore()
    await store.scanFileContent(
      manifest({ lodash: '^4.17.21', repo: 'git+https://github.com/user/repo.git' }),
    )

    expect(store.unsupportedDependencies).toHaveLength(1)
    expect(scanMock).toHaveBeenCalledTimes(1)
    expect(scanMock.mock.calls[0][0]).toHaveLength(1)
    expect(scanMock.mock.calls[0][0][0].name).toBe('lodash')
    expect(store.scanResults).toHaveLength(1)
  })

  it('deduplicates identical dependencies before scanning', async () => {
    scanMock.mockImplementation(async (deps) => deps.map(cleanResult))

    const store = useScannerStore()
    await store.scanFileContent(manifest({ lodash: '^4.17.21' }, { lodash: '~4.17.21' }))

    expect(scanMock.mock.calls[0][0]).toHaveLength(1)
    expect(store.metrics.total).toBe(1)
  })
})

describe('scanner store — cancellation and retry', () => {
  it('supports cancelling an in-flight scan', async () => {
    scanMock.mockImplementation(
      (deps, options) =>
        new Promise((resolve) => {
          options?.onProgress?.(1, deps.length)
          options?.signal?.addEventListener('abort', () => resolve([cleanResult(deps[0])]))
        }),
    )

    const store = useScannerStore()
    const scanPromise = store.scanFileContent(manifest({ alpha: '1.0.0', beta: '1.0.0' }))
    expect(store.isScanning).toBe(true)

    store.cancelScan()
    await scanPromise

    expect(store.isScanning).toBe(false)
    expect(store.isCancelled).toBe(true)
    expect(store.scanResults).toHaveLength(1)
  })

  it('retries only failed dependencies and merges the results', async () => {
    scanMock
      .mockImplementationOnce(async (deps, options) => {
        options?.onProgress?.(deps.length, deps.length)
        return [cleanResult(deps[0]), errorResult(deps[1])]
      })
      .mockImplementationOnce(async (deps, options) => {
        options?.onProgress?.(deps.length, deps.length)
        return [cleanResult(deps[0])]
      })

    const store = useScannerStore()
    await store.scanFileContent(manifest({ alpha: '1.0.0', beta: '1.0.0' }))
    expect(store.metrics.errorCount).toBe(1)

    await store.retryFailedScans()

    expect(scanMock).toHaveBeenCalledTimes(2)
    expect(scanMock.mock.calls[1][0]).toHaveLength(1)
    expect(scanMock.mock.calls[1][0][0].name).toBe('beta')
    expect(store.metrics.errorCount).toBe(0)
    expect(store.metrics.cleanCount).toBe(2)
    expect(store.isComplete).toBe(true)
  })

  it('does nothing when there are no failed scans to retry', async () => {
    scanMock.mockImplementation(async (deps) => deps.map(cleanResult))

    const store = useScannerStore()
    await store.scanFileContent(manifest({ alpha: '1.0.0' }))
    await store.retryFailedScans()

    expect(scanMock).toHaveBeenCalledTimes(1)
  })
})

describe('scanner store — advisory drawer', () => {
  it('opens and closes the advisory drawer', () => {
    const store = useScannerStore()
    const advisories = [advisory('GHSA-x')]

    store.openAdvisory('lodash', advisories)
    expect(store.selectedAdvisory).toEqual({ pkgName: 'lodash', advisories })

    store.closeAdvisory()
    expect(store.selectedAdvisory).toBeNull()
  })
})
