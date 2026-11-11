import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import App from '@/App.vue'
import { useScannerStore } from '@/stores/scannerStore'
import type { ScannedResult } from '@/types/vulnerability'
import {
  makeCleanResult,
  makeFailedResult,
  makeVulnerableResult,
} from '@/tests/helpers/fixtures'

function seedStore(
  results: ScannedResult[],
  options: { cancelled?: boolean; scanning?: boolean } = {},
) {
  const store = useScannerStore()
  store.scanResults = results
  store.totalCount = results.length
  store.scannedCount = results.length
  store.isCancelled = options.cancelled ?? false
  store.isScanning = options.scanning ?? false
  store.sourceName = 'package.json'
  return store
}

describe('App', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('shows the clean banner and dashboard metrics', () => {
    seedStore([makeCleanResult('vue', '3.5.0'), makeCleanResult('pinia', '2.1.7')])
    const wrapper = mount(App)

    expect(wrapper.text()).toContain('No known vulnerabilities found')
    expect(wrapper.text()).toContain('All 2 dependencies scanned cleanly')
    expect(wrapper.text()).toContain('Audit Overview')
    expect(wrapper.text()).toContain('Export results')
    expect(wrapper.text()).toContain('Health Score')
    wrapper.unmount()
  })

  it('shows the vulnerability banner with a conservative health score', () => {
    seedStore([makeVulnerableResult('lodash', '4.17.15'), makeCleanResult('vue', '3.5.0')])
    const wrapper = mount(App)

    expect(wrapper.text()).toContain('Vulnerabilities found in 1 of 2 dependencies')
    expect(wrapper.text()).toContain('50%')
    wrapper.unmount()
  })

  it('prioritises the cancelled banner over other states', () => {
    seedStore([makeVulnerableResult('lodash', '4.17.15'), makeFailedResult('express', '4.18.0')], {
      cancelled: true,
    })
    const wrapper = mount(App)

    expect(wrapper.text()).toContain('Scan cancelled')
    expect(wrapper.text()).not.toContain('Vulnerabilities found')
    expect(wrapper.text()).not.toContain('could not be scanned')
    wrapper.unmount()
  })

  it('offers a retry action when scans fail', async () => {
    const store = seedStore([makeFailedResult('express', '4.18.0')])
    const retrySpy = vi.spyOn(store, 'retryFailedScans').mockResolvedValue(undefined)
    const wrapper = mount(App)

    expect(wrapper.text()).toContain('1 dependencies could not be scanned')

    const retryButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('Retry failed'))
    if (!retryButton) throw new Error('Retry button not found')
    await retryButton.trigger('click')

    expect(retrySpy).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('hides the dashboard while a scan is running', () => {
    seedStore([makeCleanResult('vue', '3.5.0')], { scanning: true })
    const wrapper = mount(App)

    expect(wrapper.text()).toContain('Scanning dependencies…')
    expect(wrapper.text()).not.toContain('Audit Overview')
    wrapper.unmount()
  })
})
