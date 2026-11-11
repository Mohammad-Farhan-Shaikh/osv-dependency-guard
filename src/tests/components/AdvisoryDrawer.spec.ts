import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import AdvisoryDrawer from '@/components/AdvisoryDrawer.vue'
import { useScannerStore } from '@/stores/scannerStore'
import { makeAdvisory } from '@/tests/helpers/fixtures'

type Store = ReturnType<typeof useScannerStore>

async function openDrawer(store: Store, wrapper: VueWrapper) {
  store.selectedAdvisory = {
    pkgName: 'lodash',
    version: '4.17.15',
    advisories: [makeAdvisory()],
  }
  await flushPromises()
  return wrapper
}

function mountDrawer() {
  return mount(AdvisoryDrawer, { attachTo: document.body })
}

describe('AdvisoryDrawer', () => {
  let store: Store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useScannerStore()
  })

  afterEach(() => {
    document.body.style.overflow = ''
    document.body.innerHTML = ''
  })

  it('renders nothing while closed', () => {
    const wrapper = mountDrawer()
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('renders advisory details for the selected package', async () => {
    const wrapper = mountDrawer()
    await openDrawer(store, wrapper)

    const text = wrapper.text()
    expect(text).toContain('lodash')
    expect(text).toContain('4.17.15')
    expect(text).toContain('GHSA-test-1234')
    expect(text).toContain('High severity')
    expect(text).toContain('CVE-2021-23337')
    expect(text).toContain('>= 0, < 4.17.21')
    expect(text).toContain('4.17.21')
    expect(text).toContain('Published')
    wrapper.unmount()
  })

  it('only renders http(s) references as safe links', async () => {
    const wrapper = mountDrawer()
    store.selectedAdvisory = {
      pkgName: 'lodash',
      version: '4.17.15',
      advisories: [
        makeAdvisory({
          references: [
            { type: 'WEB', url: 'javascript:alert(1)' },
            { type: 'ADVISORY', url: 'https://example.com/safe' },
          ],
        }),
      ],
    }
    await flushPromises()

    const links = wrapper.findAll('a')
    expect(links).toHaveLength(1)
    expect(links[0].attributes('href')).toBe('https://example.com/safe')
    expect(links[0].attributes('target')).toBe('_blank')
    expect(links[0].attributes('rel')).toBe('noopener noreferrer nofollow')
    wrapper.unmount()
  })

  it('copies the advisory id to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })

    const wrapper = mountDrawer()
    await openDrawer(store, wrapper)

    const copyButton = wrapper
      .findAll('button')
      .find((button) => button.attributes('aria-label')?.startsWith('Copy advisory id'))
    if (!copyButton) throw new Error('Copy button not found')

    await copyButton.trigger('click')
    await flushPromises()

    expect(writeText).toHaveBeenCalledWith('GHSA-test-1234')
    expect(wrapper.text()).toContain('Copied')
    wrapper.unmount()
  })

  it('closes on Escape', async () => {
    const wrapper = mountDrawer()
    await openDrawer(store, wrapper)

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()

    expect(store.selectedAdvisory).toBeNull()
    wrapper.unmount()
  })

  it('moves focus to the close button and restores it on close', async () => {
    const trigger = document.createElement('button')
    document.body.appendChild(trigger)
    trigger.focus()

    const wrapper = mountDrawer()
    await openDrawer(store, wrapper)

    const closeButton = wrapper.get('[aria-label="Close advisory details"]')
    expect(document.activeElement).toBe(closeButton.element)
    expect(document.body.style.overflow).toBe('hidden')

    store.closeAdvisory()
    await flushPromises()

    expect(document.activeElement).toBe(trigger)
    expect(document.body.style.overflow).toBe('')
    wrapper.unmount()
  })

  it('traps Tab focus inside the drawer', async () => {
    const wrapper = mountDrawer()
    await openDrawer(store, wrapper)

    const links = wrapper.findAll('a')
    const lastLink = links[links.length - 1]
    const lastElement = lastLink.element as HTMLElement
    lastElement.focus()

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab' }))
    await flushPromises()

    const closeButton = wrapper.get('[aria-label="Close advisory details"]')
    expect(document.activeElement).toBe(closeButton.element)
    wrapper.unmount()
  })
})
