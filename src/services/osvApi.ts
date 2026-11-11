import type {
  AdvisoryReference,
  AffectedRange,
  DependencyItem,
  ScannedResult,
  SeverityLevel,
  VulnerabilityAdvisory,
} from '@/types/vulnerability'

export const OSV_API_URL = 'https://api.osv.dev/v1/query'

export const DEFAULT_TIMEOUT_MS = 15_000
export const DEFAULT_MAX_RETRIES = 2
export const DEFAULT_CONCURRENCY = 6
export const DEFAULT_RETRY_DELAY_MS = 500

const MAX_RETRY_DELAY_MS = 10_000
const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 504])

interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
}

interface OsvRange {
  type?: string
  events?: OsvEvent[]
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string }
  ranges?: OsvRange[]
  versions?: string[]
  database_specific?: { severity?: string }
}

interface OsvSeverity {
  type?: string
  score?: string
}

interface OsvReference {
  type?: string
  url?: string
}

interface OsvVulnerability {
  id?: string
  summary?: string
  details?: string
  aliases?: string[]
  severity?: OsvSeverity[]
  affected?: OsvAffected[]
  references?: OsvReference[]
  published?: string
  modified?: string
  database_specific?: { severity?: string }
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[] | null
}

export interface OsvRequestOptions {
  signal?: AbortSignal
  timeoutMs?: number
  maxRetries?: number
  retryDelayMs?: number
}

export interface ScanDependenciesOptions extends OsvRequestOptions {
  concurrency?: number
  onProgress?: (completed: number, total: number) => void
}

export class ScanCancelledError extends Error {
  constructor() {
    super('Scan cancelled')
    this.name = 'ScanCancelledError'
  }
}

class RequestTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Request timed out after ${timeoutMs}ms.`)
    this.name = 'RequestTimeoutError'
  }
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  return 'Unknown error'
}

function errorResult(dependency: DependencyItem, message: string): ScannedResult {
  return {
    dependency,
    isVulnerable: false,
    advisories: [],
    status: 'error',
    error: message,
  }
}

function buildResult(dependency: DependencyItem, advisories: VulnerabilityAdvisory[]): ScannedResult {
  return {
    dependency,
    isVulnerable: advisories.length > 0,
    advisories,
    status: advisories.length > 0 ? 'vulnerable' : 'clean',
  }
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ScanCancelledError())
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(new ScanCancelledError())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function retryDelay(attempt: number, baseMs: number, response?: Response): number {
  const retryAfter = response?.headers?.get?.('retry-after')
  if (retryAfter) {
    const seconds = Number(retryAfter)
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, MAX_RETRY_DELAY_MS)
    }
  }
  return Math.min(baseMs * 2 ** attempt, MAX_RETRY_DELAY_MS)
}

async function requestWithTimeout(
  body: string,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController()
  let timedOut = false

  const onAbort = () => controller.abort()
  if (signal?.aborted) controller.abort()
  signal?.addEventListener('abort', onAbort, { once: true })

  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)

  try {
    return await fetch(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal,
    })
  } catch (error) {
    if (timedOut) throw new RequestTimeoutError(timeoutMs)
    throw error
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}

function safeText(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim().length > 0 ? value : fallback
}

function normalizeSeverity(value: unknown): SeverityLevel | null {
  if (typeof value !== 'string') return null
  const upper = value.toUpperCase()
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'LOW') return upper
  if (upper === 'MODERATE' || upper === 'MEDIUM') return 'MODERATE'
  return null
}

function resolveSeverity(
  vuln: OsvVulnerability,
  matchingAffected: OsvAffected[],
): SeverityLevel {
  const fromTopLevel = normalizeSeverity(vuln.database_specific?.severity)
  if (fromTopLevel) return fromTopLevel

  for (const affected of matchingAffected) {
    const fromAffected = normalizeSeverity(affected.database_specific?.severity)
    if (fromAffected) return fromAffected
  }

  return 'UNKNOWN'
}

function extractRanges(matchingAffected: OsvAffected[]): AffectedRange[] {
  const ranges: AffectedRange[] = []

  for (const affected of matchingAffected) {
    for (const range of affected.ranges ?? []) {
      let introduced: string | undefined
      for (const event of range.events ?? []) {
        if (typeof event.introduced === 'string') {
          introduced = event.introduced
        }
        if (typeof event.fixed === 'string') {
          ranges.push({ type: range.type ?? 'ECOSYSTEM', introduced, fixed: event.fixed })
          introduced = undefined
        }
        if (typeof event.last_affected === 'string') {
          ranges.push({
            type: range.type ?? 'ECOSYSTEM',
            introduced,
            fixed: event.last_affected,
          })
          introduced = undefined
        }
      }
      if (introduced !== undefined) {
        ranges.push({ type: range.type ?? 'ECOSYSTEM', introduced })
      }
    }
  }

  return ranges
}

function collectFixedVersions(matchingAffected: OsvAffected[]): string[] {
  const fixed = new Set<string>()

  for (const affected of matchingAffected) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (typeof event.fixed === 'string' && event.fixed.length > 0) {
          fixed.add(event.fixed)
        }
      }
    }
  }

  return [...fixed]
}

function extractReferences(references: OsvReference[] | undefined): AdvisoryReference[] {
  if (!Array.isArray(references)) return []

  return references
    .filter((reference): reference is OsvReference & { url: string } => {
      return typeof reference?.url === 'string' && reference.url.length > 0
    })
    .map((reference) => ({
      type: typeof reference.type === 'string' && reference.type.length > 0
        ? reference.type
        : 'WEB',
      url: reference.url,
    }))
}

function extractCvssVector(severity: OsvSeverity[] | undefined): string | undefined {
  if (!Array.isArray(severity)) return undefined
  const entry = severity.find((item) => typeof item?.score === 'string' && item.score.length > 0)
  return entry?.score
}

function isOsvVulnerability(value: unknown): value is OsvVulnerability {
  if (typeof value !== 'object' || value === null) return false
  const id = (value as OsvVulnerability).id
  return typeof id === 'string' && id.length > 0
}

function mapVulnerability(
  vuln: OsvVulnerability,
  dependency: DependencyItem,
): VulnerabilityAdvisory {
  const affectedEntries = Array.isArray(vuln.affected) ? vuln.affected : []
  const matchingAffected = affectedEntries.filter((entry) => {
    const packageName = entry.package?.name
    return typeof packageName !== 'string' || packageName === dependency.name
  })

  const fixedVersions = collectFixedVersions(matchingAffected)

  return {
    id: vuln.id as string,
    summary: safeText(vuln.summary, 'Security advisory reported for this dependency version.'),
    details: safeText(vuln.details, 'No extended description available.'),
    aliases: Array.isArray(vuln.aliases)
      ? vuln.aliases.filter((alias): alias is string => typeof alias === 'string')
      : [],
    severity: resolveSeverity(vuln, matchingAffected),
    fixedVersion: fixedVersions[0],
    fixedVersions,
    affectedRanges: extractRanges(matchingAffected),
    references: extractReferences(vuln.references),
    published: typeof vuln.published === 'string' ? vuln.published : undefined,
    modified: typeof vuln.modified === 'string' ? vuln.modified : undefined,
    cvssVector: extractCvssVector(vuln.severity),
  }
}

function mapResponse(dependency: DependencyItem, data: unknown): ScannedResult {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return errorResult(dependency, 'OSV API returned an unexpected response shape.')
  }

  const { vulns } = data as OsvQueryResponse

  if (vulns === undefined || vulns === null) {
    return buildResult(dependency, [])
  }
  if (!Array.isArray(vulns)) {
    return errorResult(dependency, 'OSV API returned an unexpected "vulns" field.')
  }

  const advisories: VulnerabilityAdvisory[] = []
  for (const entry of vulns) {
    if (!isOsvVulnerability(entry)) {
      return errorResult(dependency, 'OSV API returned a vulnerability entry without an id.')
    }
    advisories.push(mapVulnerability(entry, dependency))
  }

  return buildResult(dependency, advisories)
}

export async function checkDependency(
  dependency: DependencyItem,
  options: OsvRequestOptions = {},
): Promise<ScannedResult> {
  const {
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRetries = DEFAULT_MAX_RETRIES,
    retryDelayMs = DEFAULT_RETRY_DELAY_MS,
  } = options

  const body = JSON.stringify({
    package: { name: dependency.name, ecosystem: dependency.ecosystem },
    version: dependency.version,
  })

  let lastError = 'Unknown error'

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    if (signal?.aborted) throw new ScanCancelledError()

    let response: Response
    try {
      response = await requestWithTimeout(body, signal, timeoutMs)
    } catch (error) {
      if (signal?.aborted || error instanceof ScanCancelledError) {
        throw new ScanCancelledError()
      }
      lastError = error instanceof RequestTimeoutError
        ? error.message
        : `Network error: ${toErrorMessage(error)}`

      if (attempt < maxRetries) {
        await delay(retryDelay(attempt, retryDelayMs), signal)
        continue
      }
      return errorResult(dependency, lastError)
    }

    if (!response.ok) {
      if (RETRYABLE_STATUS_CODES.has(response.status) && attempt < maxRetries) {
        await delay(retryDelay(attempt, retryDelayMs, response), signal)
        continue
      }
      return errorResult(dependency, `OSV API responded with HTTP ${response.status}.`)
    }

    let data: unknown
    try {
      data = await response.json()
    } catch {
      return errorResult(dependency, 'OSV API returned malformed JSON.')
    }

    return mapResponse(dependency, data)
  }

  return errorResult(dependency, lastError)
}

export async function scanDependencies(
  dependencies: DependencyItem[],
  options: ScanDependenciesOptions = {},
): Promise<ScannedResult[]> {
  const { concurrency = DEFAULT_CONCURRENCY, onProgress, signal } = options
  const total = dependencies.length

  if (total === 0) return []

  const slots: Array<ScannedResult | undefined> = new Array(total)
  let nextIndex = 0
  let completed = 0

  const runWorker = async (): Promise<void> => {
    while (true) {
      if (signal?.aborted) return
      const index = nextIndex
      nextIndex += 1
      if (index >= total) return

      const dependency = dependencies[index]
      try {
        slots[index] = await checkDependency(dependency, options)
      } catch (error) {
        if (error instanceof ScanCancelledError || signal?.aborted) return
        slots[index] = errorResult(dependency, toErrorMessage(error))
      }

      completed += 1
      onProgress?.(completed, total)
    }
  }

  const workerCount = Math.max(1, Math.min(concurrency, total))
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()))

  return slots.filter((slot): slot is ScannedResult => slot !== undefined)
}
