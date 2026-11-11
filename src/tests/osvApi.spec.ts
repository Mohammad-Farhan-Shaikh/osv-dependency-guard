import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  OSV_API_URL,
  ScanCancelledError,
  checkDependency,
  scanDependencies,
} from '../services/osvApi'
import type { DependencyItem, SeverityLevel } from '../types/vulnerability'

const lodash: DependencyItem = { name: 'lodash', version: '4.17.15', ecosystem: 'npm' }

function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const status = init.status ?? 200
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(init.headers),
    json: async () => body,
  } as unknown as Response
}

function hangingFetch(): ReturnType<typeof vi.fn> {
  return vi.fn((_url: string, init: RequestInit) => {
    return new Promise<Response>((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'))
      })
    })
  })
}

const vulnerablePayload = {
  vulns: [
    {
      id: 'GHSA-35jh-r3h4-6jhm',
      summary: 'Command injection in lodash',
      details: 'A command injection vulnerability exists in lodash template.',
      aliases: ['CVE-2021-23337'],
      severity: [
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' },
      ],
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
        },
      ],
      references: [
        { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' },
      ],
      published: '2021-02-15T00:00:00Z',
      modified: '2023-01-01T00:00:00Z',
      database_specific: { severity: 'HIGH' },
    },
  ],
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('checkDependency — request', () => {
  it('posts package name, ecosystem and version to the OSV endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}))
    vi.stubGlobal('fetch', fetchMock)

    await checkDependency(lodash)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(OSV_API_URL)
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({
      package: { name: 'lodash', ecosystem: 'npm' },
      version: '4.17.15',
    })
  })
})

describe('checkDependency — successful responses', () => {
  it('returns a clean result when no vulnerabilities are reported', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({})))

    const result = await checkDependency(lodash)

    expect(result.status).toBe('clean')
    expect(result.isVulnerable).toBe(false)
    expect(result.advisories).toEqual([])
  })

  it('returns a clean result for an empty vulns array', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ vulns: [] })))

    const result = await checkDependency(lodash)

    expect(result.status).toBe('clean')
  })

  it('maps a vulnerability advisory accurately', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(vulnerablePayload)))

    const result = await checkDependency(lodash)

    expect(result.status).toBe('vulnerable')
    expect(result.isVulnerable).toBe(true)
    expect(result.advisories).toHaveLength(1)

    const advisory = result.advisories[0]
    expect(advisory.id).toBe('GHSA-35jh-r3h4-6jhm')
    expect(advisory.summary).toBe('Command injection in lodash')
    expect(advisory.details).toContain('command injection')
    expect(advisory.aliases).toEqual(['CVE-2021-23337'])
    expect(advisory.severity).toBe('HIGH')
    expect(advisory.fixedVersion).toBe('4.17.21')
    expect(advisory.fixedVersions).toEqual(['4.17.21'])
    expect(advisory.affectedRanges).toEqual([
      { type: 'SEMVER', introduced: '0', fixed: '4.17.21' },
    ])
    expect(advisory.references).toEqual([
      { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' },
    ])
    expect(advisory.cvssVector).toBe('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H')
    expect(advisory.published).toBe('2021-02-15T00:00:00Z')
    expect(advisory.modified).toBe('2023-01-01T00:00:00Z')
  })

  it('collects fixed versions from every matching affected entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse({
          vulns: [
            {
              id: 'GHSA-multi',
              affected: [
                {
                  package: { name: 'lodash', ecosystem: 'npm' },
                  ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
                },
                {
                  package: { name: 'lodash', ecosystem: 'npm' },
                  ranges: [{ type: 'SEMVER', events: [{ introduced: '4.17.22' }, { fixed: '4.17.25' }] }],
                },
                {
                  package: { name: 'lodash-es', ecosystem: 'npm' },
                  ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }],
                },
              ],
            },
          ],
        }),
      ),
    )

    const result = await checkDependency(lodash)

    expect(result.advisories[0].fixedVersions).toEqual(['4.17.21', '4.17.25'])
    expect(result.advisories[0].fixedVersion).toBe('4.17.21')
  })

  it('uses safe defaults for missing optional advisory fields', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ vulns: [{ id: 'OSV-MINIMAL' }] })),
    )

    const result = await checkDependency(lodash)
    const advisory = result.advisories[0]

    expect(advisory.id).toBe('OSV-MINIMAL')
    expect(advisory.summary).toBeTruthy()
    expect(advisory.details).toBeTruthy()
    expect(advisory.aliases).toEqual([])
    expect(advisory.severity).toBe('UNKNOWN')
    expect(advisory.fixedVersion).toBeUndefined()
    expect(advisory.fixedVersions).toEqual([])
    expect(advisory.affectedRanges).toEqual([])
    expect(advisory.references).toEqual([])
  })
})

describe('checkDependency — severity mapping', () => {
  const cases: Array<[string | undefined, SeverityLevel]> = [
    ['CRITICAL', 'CRITICAL'],
    ['HIGH', 'HIGH'],
    ['MODERATE', 'MODERATE'],
    ['MEDIUM', 'MODERATE'],
    ['low', 'LOW'],
    ['SEVERE', 'UNKNOWN'],
    [undefined, 'UNKNOWN'],
  ]

  it.each(cases)('maps database_specific severity "%s" to %s', async (raw, expected) => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse({
          vulns: [
            {
              id: 'GHSA-sev',
              database_specific: raw === undefined ? {} : { severity: raw },
            },
          ],
        }),
      ),
    )

    const result = await checkDependency(lodash)

    expect(result.advisories[0].severity).toBe(expected)
  })
})

describe('checkDependency — error handling', () => {
  it('returns an error result for non-retryable HTTP errors', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}, { status: 400 }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await checkDependency(lodash)

    expect(result.status).toBe('error')
    expect(result.isVulnerable).toBe(false)
    expect(result.error).toContain('HTTP 400')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries transient HTTP errors and succeeds', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, { status: 500 }))
      .mockResolvedValueOnce(jsonResponse({}))
    vi.stubGlobal('fetch', fetchMock)

    const result = await checkDependency(lodash, { retryDelayMs: 0 })

    expect(result.status).toBe('clean')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('honours the Retry-After header on 429 responses', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, { status: 429, headers: { 'retry-after': '0' } }))
      .mockResolvedValueOnce(jsonResponse({}))
    vi.stubGlobal('fetch', fetchMock)

    const result = await checkDependency(lodash, { retryDelayMs: 0 })

    expect(result.status).toBe('clean')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('returns an error result after exhausting retries', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}, { status: 503 }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await checkDependency(lodash, { maxRetries: 1, retryDelayMs: 0 })

    expect(result.status).toBe('error')
    expect(result.error).toContain('HTTP 503')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('returns an error result for network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))

    const result = await checkDependency(lodash, { maxRetries: 0 })

    expect(result.status).toBe('error')
    expect(result.error).toContain('Network error')
  })

  it('returns an error result when the request times out', async () => {
    vi.stubGlobal('fetch', hangingFetch())

    const result = await checkDependency(lodash, { timeoutMs: 5, maxRetries: 0 })

    expect(result.status).toBe('error')
    expect(result.error).toMatch(/timed out/)
  })

  it('returns an error result for malformed JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => {
          throw new SyntaxError('Unexpected token')
        },
      } as unknown as Response),
    )

    const result = await checkDependency(lodash)

    expect(result.status).toBe('error')
    expect(result.error).toMatch(/malformed JSON/i)
  })

  it.each([
    ['an array', []],
    ['a string', 'nope'],
    ['null', null],
    ['an invalid vulns field', { vulns: 'nope' }],
  ])('returns an error result for %s', async (_label, payload) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(payload)))

    const result = await checkDependency(lodash)

    expect(result.status).toBe('error')
  })

  it('never reports a vulnerability entry without an id as clean', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ vulns: [{ summary: 'no id here' }] })),
    )

    const result = await checkDependency(lodash)

    expect(result.status).toBe('error')
    expect(result.isVulnerable).toBe(false)
  })
})

describe('checkDependency — cancellation', () => {
  it('rejects when the signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(checkDependency(lodash, { signal: controller.signal })).rejects.toBeInstanceOf(
      ScanCancelledError,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects when aborted mid-flight', async () => {
    vi.stubGlobal('fetch', hangingFetch())
    const controller = new AbortController()

    const promise = checkDependency(lodash, { signal: controller.signal, timeoutMs: 5_000 })
    controller.abort()

    await expect(promise).rejects.toBeInstanceOf(ScanCancelledError)
  })
})

describe('scanDependencies', () => {
  const deps: DependencyItem[] = [
    { name: 'pkg-1', version: '1.0.0', ecosystem: 'npm' },
    { name: 'pkg-2', version: '1.0.0', ecosystem: 'npm' },
    { name: 'pkg-3', version: '1.0.0', ecosystem: 'npm' },
  ]

  it('returns an empty array for no dependencies', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const results = await scanDependencies([])

    expect(results).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('scans every dependency and reports progress', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({})))
    const progress: Array<[number, number]> = []

    const results = await scanDependencies(deps, {
      concurrency: 1,
      onProgress: (completed, total) => progress.push([completed, total]),
    })

    expect(results).toHaveLength(3)
    expect(results.every((result) => result.status === 'clean')).toBe(true)
    expect(progress).toEqual([
      [1, 3],
      [2, 3],
      [3, 3],
    ])
  })

  it('respects the concurrency limit', async () => {
    let inFlight = 0
    let maxInFlight = 0

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        inFlight += 1
        maxInFlight = Math.max(maxInFlight, inFlight)
        await new Promise((resolve) => setTimeout(resolve, 5))
        inFlight -= 1
        return jsonResponse({})
      }),
    )

    const results = await scanDependencies(deps, { concurrency: 2 })

    expect(results).toHaveLength(3)
    expect(maxInFlight).toBeLessThanOrEqual(2)
  })

  it('preserves input order regardless of completion order', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: RequestInit) => {
        const body = JSON.parse(String(init.body))
        const wait = body.package.name === 'slow' ? 20 : 1
        await new Promise((resolve) => setTimeout(resolve, wait))
        return jsonResponse({ vulns: [{ id: `VULN-${body.package.name}` }] })
      }),
    )

    const results = await scanDependencies(
      [
        { name: 'slow', version: '1.0.0', ecosystem: 'npm' },
        { name: 'fast', version: '1.0.0', ecosystem: 'npm' },
      ],
      { concurrency: 2 },
    )

    expect(results.map((result) => result.dependency.name)).toEqual(['slow', 'fast'])
  })

  it('captures per-dependency failures without failing the whole scan', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))

    const results = await scanDependencies(deps, { maxRetries: 0 })

    expect(results).toHaveLength(3)
    expect(results.every((result) => result.status === 'error')).toBe(true)
  })

  it('returns partial results when the scan is cancelled', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const results = await scanDependencies(deps, { signal: controller.signal })

    expect(results).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
