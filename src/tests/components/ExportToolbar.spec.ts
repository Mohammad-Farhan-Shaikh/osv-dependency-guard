import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ExportToolbar from '@/components/ExportToolbar.vue'
import { useScannerStore } from '@/stores/scannerStore'
import { makeCleanResult, makeVulnerableResult } from '@/tests/helpers/fixtures'

const { downloadTextFileMock } = vi.hoisted(() => ({ downloadTextFileMock: vi.fn() }))

vi.mock('@/utils/download', () => ({
  downloadTextFile: downloadTextFileMock,
}))

function mountToolbar() {
  return mount(ExportToolbar)
}

function buttonByText(wrapper: ReturnType<typeof mountToolbar>, label: string) {
  const button = wrapper.findAll('button').find((candidate) => candidate.text().includes(label))
  if (!button) throw new Error(`Button not found: ${label}`)
  return button
}

describe('ExportToolbar', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    downloadTextFileMock.mockReset()

    const store = useScannerStore()
    store.scanResults = [makeVulnerableResult('lodash', '4.17.15'), makeCleanResult('vue', '3.5.0')]
    store.sourceName = 'package.json'
  })

  it('exports a JSON report', async () => {
    const wrapper = mountToolbar()
    await buttonByText(wrapper, 'Export JSON').trigger('click')

    expect(downloadTextFileMock).toHaveBeenCalledTimes(1)
    const [filename, content, mimeType] = downloadTextFileMock.mock.calls[0]

    expect(filename).toMatch(/^depguard-package-json-.+\.json$/)
    expect(mimeType).toBe('application/json')
    expect(JSON.parse(content).results).toHaveLength(2)
  })

  it('exports a UTF-8 BOM CSV report', async () => {
    const wrapper = mountToolbar()
    await buttonByText(wrapper, 'Export CSV').trigger('click')

    const [filename, content, mimeType] = downloadTextFileMock.mock.calls[0]

    expect(filename).toMatch(/^depguard-package-json-.+\.csv$/)
    expect(mimeType).toBe('text/csv')
    expect(content.startsWith('\uFEFFPackage,Version')).toBe(true)
  })

  it('downloads a Markdown report', async () => {
    const wrapper = mountToolbar()
    await buttonByText(wrapper, 'Download report').trigger('click')

    const [filename, content, mimeType] = downloadTextFileMock.mock.calls[0]

    expect(filename).toMatch(/^depguard-package-json-.+\.md$/)
    expect(mimeType).toBe('text/markdown')
    expect(content).toContain('# DepGuard Security Report')
    expect(content).toContain('### lodash `4.17.15`')
  })
})
