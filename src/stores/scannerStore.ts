import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type {
  DependencyItem,
  ScannedResult,
  ScanMetrics,
  UnsupportedDependency,
  VulnerabilityAdvisory,
} from '@/types/vulnerability'
import { parsePackageJson } from '@/utils/parser'
import { ScanCancelledError, scanDependencies } from '@/services/osvApi'

function dedupeDependencies(dependencies: DependencyItem[]): DependencyItem[] {
  const unique = new Map<string, DependencyItem>()
  for (const dependency of dependencies) {
    unique.set(`${dependency.name}@${dependency.version}`, dependency)
  }
  return [...unique.values()]
}

function toErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback
}

export const useScannerStore = defineStore('scanner', () => {
  const isScanning = ref(false)
  const isCancelled = ref(false)
  const scanResults = ref<ScannedResult[]>([])
  const unsupportedDependencies = ref<UnsupportedDependency[]>([])
  const manifestWarnings = ref<string[]>([])
  const selectedAdvisory = ref<{ pkgName: string; advisories: VulnerabilityAdvisory[] } | null>(
    null,
  )
  const errorMessage = ref<string | null>(null)
  const scannedCount = ref(0)
  const totalCount = ref(0)
  const sourceName = ref<string | null>(null)
  const lastScanAt = ref<string | null>(null)

  let activeController: AbortController | null = null

  const isComplete = computed(
    () =>
      !isScanning.value &&
      totalCount.value > 0 &&
      scannedCount.value >= totalCount.value &&
      !isCancelled.value,
  )

  const hasFailures = computed(() =>
    scanResults.value.some((result) => result.status === 'error'),
  )

  const hasVulnerabilities = computed(() =>
    scanResults.value.some((result) => result.status === 'vulnerable'),
  )

  const metrics = computed<ScanMetrics>(() => {
    const results = scanResults.value
    const total = results.length
    const vulnerableCount = results.filter((result) => result.status === 'vulnerable').length
    const cleanCount = results.filter((result) => result.status === 'clean').length
    const errorCount = results.filter((result) => result.status === 'error').length
    const healthScore = total === 0 ? 100 : Math.round((cleanCount / total) * 100)
    const pendingCount = Math.max(0, totalCount.value - scannedCount.value)

    return {
      total,
      vulnerableCount,
      cleanCount,
      errorCount,
      pendingCount,
      healthScore,
      isComplete: isComplete.value,
    }
  })

  async function scanFileContent(rawJson: string, fileName?: string) {
    if (isScanning.value) return

    isScanning.value = true
    isCancelled.value = false
    errorMessage.value = null
    scanResults.value = []
    unsupportedDependencies.value = []
    manifestWarnings.value = []
    scannedCount.value = 0
    totalCount.value = 0
    sourceName.value = fileName ?? null
    lastScanAt.value = null

    try {
      const manifest = parsePackageJson(rawJson)
      unsupportedDependencies.value = manifest.unsupported
      manifestWarnings.value = manifest.warnings

      if (manifest.dependencies.length === 0) {
        throw new Error(
          manifest.unsupported.length > 0
            ? 'No scannable dependencies found — every entry uses an unsupported format (git, file, workspace, tag or range).'
            : 'No dependencies found in manifest.',
        )
      }

      const dependencies = dedupeDependencies(manifest.dependencies)
      totalCount.value = dependencies.length

      const controller = new AbortController()
      activeController = controller

      scanResults.value = await scanDependencies(dependencies, {
        signal: controller.signal,
        onProgress: (completed, total) => {
          scannedCount.value = completed
          totalCount.value = total
        },
      })

      if (controller.signal.aborted) {
        isCancelled.value = true
      }
    } catch (error) {
      if (error instanceof ScanCancelledError) {
        isCancelled.value = true
      } else {
        errorMessage.value = toErrorMessage(error, 'Failed to parse manifest file.')
      }
    } finally {
      activeController = null
      isScanning.value = false
      if (!errorMessage.value) {
        lastScanAt.value = new Date().toISOString()
      }
    }
  }

  async function retryFailedScans() {
    if (isScanning.value) return

    const failedResults = scanResults.value.filter((result) => result.status === 'error')
    if (failedResults.length === 0) return

    isScanning.value = true
    isCancelled.value = false
    errorMessage.value = null

    const failedDependencies = failedResults.map((result) => result.dependency)
    const alreadyCompleted = scanResults.value.length - failedDependencies.length

    const controller = new AbortController()
    activeController = controller

    scannedCount.value = alreadyCompleted
    totalCount.value = scanResults.value.length

    try {
      const retried = await scanDependencies(failedDependencies, {
        signal: controller.signal,
        onProgress: (completed) => {
          scannedCount.value = alreadyCompleted + completed
        },
      })

      const retriedByKey = new Map(
        retried.map((result) => [
          `${result.dependency.name}@${result.dependency.version}`,
          result,
        ]),
      )

      scanResults.value = scanResults.value.map((result) => {
        if (result.status !== 'error') return result
        const key = `${result.dependency.name}@${result.dependency.version}`
        return retriedByKey.get(key) ?? result
      })

      if (controller.signal.aborted) {
        isCancelled.value = true
      }
    } catch (error) {
      errorMessage.value = toErrorMessage(error, 'Failed to retry failed scans.')
    } finally {
      activeController = null
      isScanning.value = false
      if (!errorMessage.value) {
        lastScanAt.value = new Date().toISOString()
      }
    }
  }

  function cancelScan() {
    activeController?.abort()
  }

  function openAdvisory(pkgName: string, advisories: VulnerabilityAdvisory[]) {
    selectedAdvisory.value = { pkgName, advisories }
  }

  function closeAdvisory() {
    selectedAdvisory.value = null
  }

  return {
    isScanning,
    isCancelled,
    scanResults,
    unsupportedDependencies,
    manifestWarnings,
    selectedAdvisory,
    errorMessage,
    scannedCount,
    totalCount,
    sourceName,
    lastScanAt,
    metrics,
    isComplete,
    hasFailures,
    hasVulnerabilities,
    scanFileContent,
    retryFailedScans,
    cancelScan,
    openAdvisory,
    closeAdvisory,
  }
})
