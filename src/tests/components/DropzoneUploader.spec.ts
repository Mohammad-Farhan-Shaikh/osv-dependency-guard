import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import DropzoneUploader from '@/components/DropzoneUploader.vue'
import { useScannerStore } from '@/stores/scannerStore'
import { makeCleanResult } from '@/tests/helpers/fixtures'

type Store = ReturnType<typeof useScannerStore>

function mountUploader() {
  return mount(DropzoneUploader)
}

async function dropFile(wrapper: ReturnType<typeof mountUploader>, file: File) {
  await wrapper.get('[role="button"]').trigger('drop', { dataTransfer: { files: [file] } })
}

describe('DropzoneUploader', () => {
  let store: Store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useScannerStore()
  })

  it('rejects non-JSON files', async () => {
    const wrapper = mountUploader()
    await dropFile(wrapper, new File(['{}'], 'package.txt', { type: 'text/plain' }))

    expect(wrapper.get('[role="alert"]').text()).toContain('Only .json manifest files are supported.')
  })

  it('rejects empty files', async () => {
    const wrapper = mountUploader()
    await dropFile(wrapper, new File([], 'package.json', { type: 'application/json' }))

    expect(wrapper.get('[role="alert"]').text()).toContain('The selected file is empty.')
  })

  it('rejects files larger than 2 MB', async () => {
    const wrapper = mountUploader()
    const oversized = new File([new Uint8Array(2 * 1024 * 1024 + 1)], 'package.json', {
      type: 'application/json',
    })
    await dropFile(wrapper, oversized)

    expect(wrapper.get('[role="alert"]').text()).toContain('File is too large')
  })

  it('reads a valid manifest and starts a scan', async () => {
    const scanSpy = vi.spyOn(store, 'scanFileContent').mockResolvedValue(undefined)
    const wrapper = mountUploader()
    const content = '{"dependencies":{"lodash":"4.17.15"}}'

    await dropFile(wrapper, new File([content], 'package.json', { type: 'application/json' }))

    await vi.waitFor(() => {
      expect(scanSpy).toHaveBeenCalledWith(content, 'package.json')
    })
  })

  it('loads the demo manifest from the sample button', async () => {
    const scanSpy = vi.spyOn(store, 'scanFileContent').mockResolvedValue(undefined)
    const wrapper = mountUploader()

    const demoButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('Load demo vulnerable manifest'))
    if (!demoButton) throw new Error('Demo button not found')

    await demoButton.trigger('click')

    expect(scanSpy).toHaveBeenCalledTimes(1)
    const [content, fileName] = scanSpy.mock.calls[0]
    expect(content).toContain('"lodash": "4.17.15"')
    expect(fileName).toBe('demo-manifest.json')
  })

  it('shows progress and allows cancelling an active scan', async () => {
    const cancelSpy = vi.spyOn(store, 'cancelScan').mockImplementation(() => {})
    store.isScanning = true
    store.scannedCount = 1
    store.totalCount = 4

    const wrapper = mountUploader()

    expect(wrapper.get('[role="progressbar"]').attributes('aria-valuenow')).toBe('25')
    expect(wrapper.text()).toContain('Checking 1 of 4 dependencies')
    expect(wrapper.get('[role="button"]').attributes('aria-disabled')).toBe('true')

    const cancelButton = wrapper.findAll('button').find((button) => button.text().includes('Cancel scan'))
    if (!cancelButton) throw new Error('Cancel button not found')
    await cancelButton.trigger('click')

    expect(cancelSpy).toHaveBeenCalledTimes(1)
  })

  it('reports a completed scan summary', () => {
    store.scanResults = [makeCleanResult('vue', '3.5.0')]
    store.totalCount = 1
    store.scannedCount = 1
    store.sourceName = 'package.json'

    const wrapper = mountUploader()

    expect(wrapper.get('[role="status"]').text()).toContain('Scanned 1 dependencies')
    expect(wrapper.get('[role="status"]').text()).toContain('from package.json')
  })
})
