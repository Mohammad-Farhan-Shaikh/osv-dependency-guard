<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { Check, Copy, ExternalLink, ShieldAlert, X } from 'lucide-vue-next'
import { useScannerStore } from '@/stores/scannerStore'
import type { AffectedRange } from '@/types/vulnerability'
import { SEVERITY_LABELS, SEVERITY_TEXT_CLASS } from '@/utils/severity'

const store = useScannerStore()

const drawerRef = ref<HTMLElement | null>(null)
const closeButtonRef = ref<HTMLButtonElement | null>(null)
const copiedId = ref<string | null>(null)

let previouslyFocused: HTMLElement | null = null
let copyTimer: ReturnType<typeof setTimeout> | null = null

const entries = computed(() => {
  const selected = store.selectedAdvisory
  if (!selected) return []

  return selected.advisories.map((advisory) => ({
    advisory,
    references: advisory.references.filter((reference) => isSafeUrl(reference.url)),
  }))
})

function isSafeUrl(url: string): boolean {
  return /^https?:\/\//i.test(url)
}

function formatRange(range: AffectedRange): string {
  if (range.introduced && range.fixed) return `>= ${range.introduced}, < ${range.fixed}`
  if (range.introduced) return `>= ${range.introduced}`
  if (range.fixed) return `< ${range.fixed}`
  return 'Unknown range'
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

async function copyId(id: string) {
  try {
    await navigator.clipboard.writeText(id)
    copiedId.value = id
    if (copyTimer) clearTimeout(copyTimer)
    copyTimer = setTimeout(() => {
      copiedId.value = null
    }, 1500)
  } catch {
    copiedId.value = null
  }
}

function trapFocus(event: KeyboardEvent) {
  const container = drawerRef.value
  if (!container) return

  const focusable = Array.from(
    container.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])',
    ),
  )
  if (focusable.length === 0) return

  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  const active = document.activeElement

  if (event.shiftKey) {
    if (active === first || !container.contains(active)) {
      event.preventDefault()
      last.focus()
    }
    return
  }

  if (active === last || !container.contains(active)) {
    event.preventDefault()
    first.focus()
  }
}

function onKeydown(event: KeyboardEvent) {
  if (!store.selectedAdvisory) return

  if (event.key === 'Escape') {
    store.closeAdvisory()
    return
  }

  if (event.key === 'Tab') {
    trapFocus(event)
  }
}

watch(
  () => store.selectedAdvisory,
  async (advisory) => {
    if (advisory) {
      previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null
      document.body.style.overflow = 'hidden'
      await nextTick()
      closeButtonRef.value?.focus()
      return
    }

    document.body.style.overflow = ''
    previouslyFocused?.focus()
    previouslyFocused = null
  },
)

onMounted(() => window.addEventListener('keydown', onKeydown))

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  document.body.style.overflow = ''
  if (copyTimer) clearTimeout(copyTimer)
})
</script>

<template>
  <div
    v-if="store.selectedAdvisory"
    class="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end"
    @click.self="store.closeAdvisory()"
  >
    <div
      ref="drawerRef"
      class="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-labelledby="advisory-title"
    >
      <div class="p-6 border-b border-slate-800 flex items-start justify-between gap-3">
        <div class="flex items-center gap-3 min-w-0">
          <ShieldAlert class="w-6 h-6 text-rose-500 shrink-0" aria-hidden="true" />
          <div class="min-w-0">
            <h2 id="advisory-title" class="text-lg font-bold text-white font-mono truncate">
              {{ store.selectedAdvisory.pkgName }}
            </h2>
            <p class="text-xs text-slate-400">
              Installed version
              <span class="font-mono">{{ store.selectedAdvisory.version }}</span>
            </p>
          </div>
        </div>
        <button
          ref="closeButtonRef"
          type="button"
          class="p-1 rounded-lg text-slate-400 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          aria-label="Close advisory details"
          @click="store.closeAdvisory()"
        >
          <X class="w-5 h-5" aria-hidden="true" />
        </button>
      </div>

      <div class="flex-1 overflow-y-auto p-6 space-y-4">
        <article
          v-for="entry in entries"
          :key="entry.advisory.id"
          class="bg-slate-950 border border-slate-800 rounded-lg p-5"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span
                class="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded"
              >
                {{ entry.advisory.id }}
              </span>
              <button
                type="button"
                class="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white"
                :aria-label="`Copy advisory id ${entry.advisory.id}`"
                @click="copyId(entry.advisory.id)"
              >
                <component
                  :is="copiedId === entry.advisory.id ? Check : Copy"
                  class="w-3.5 h-3.5"
                  aria-hidden="true"
                />
                {{ copiedId === entry.advisory.id ? 'Copied' : 'Copy' }}
              </button>
            </div>
            <span
              class="text-xs font-semibold uppercase tracking-wide"
              :class="SEVERITY_TEXT_CLASS[entry.advisory.severity]"
            >
              {{ SEVERITY_LABELS[entry.advisory.severity] }} severity
            </span>
          </div>

          <h4 class="text-sm font-semibold text-white mt-3">{{ entry.advisory.summary }}</h4>

          <div v-if="entry.advisory.aliases.length" class="mt-2 flex flex-wrap gap-1.5">
            <span
              v-for="alias in entry.advisory.aliases"
              :key="alias"
              class="text-[11px] font-mono text-slate-300 bg-slate-800 px-1.5 py-0.5 rounded"
            >
              {{ alias }}
            </span>
          </div>

          <div class="mt-3">
            <p class="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Description</p>
            <p
              v-if="entry.advisory.details"
              class="text-xs text-slate-400 leading-relaxed whitespace-pre-wrap break-words max-h-64 overflow-y-auto"
            >
              {{ entry.advisory.details }}
            </p>
            <p v-else class="text-xs text-slate-500">No description provided.</p>
          </div>

          <div v-if="entry.advisory.affectedRanges.length" class="mt-3">
            <p class="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Affected versions</p>
            <ul class="space-y-1">
              <li
                v-for="(range, index) in entry.advisory.affectedRanges"
                :key="index"
                class="text-xs text-slate-300 font-mono flex items-center gap-2"
              >
                <span class="text-[10px] uppercase text-slate-500">{{ range.type }}</span>
                <span>{{ formatRange(range) }}</span>
              </li>
            </ul>
          </div>

          <div
            v-if="entry.advisory.fixedVersions.length"
            class="mt-3 p-3 bg-emerald-950/40 border border-emerald-800/40 rounded text-xs text-emerald-300"
          >
            <p class="font-semibold">Recommended fix</p>
            <p class="mt-0.5">
              Upgrade to
              <span class="font-mono font-bold">{{ entry.advisory.fixedVersions.join(' or ') }}</span>
              or higher.
            </p>
          </div>

          <div v-if="entry.references.length" class="mt-3">
            <p class="text-[11px] uppercase tracking-wide text-slate-500 mb-1">References</p>
            <ul class="space-y-1">
              <li v-for="reference in entry.references" :key="reference.url">
                <a
                  :href="reference.url"
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  class="inline-flex items-start gap-1 text-xs text-indigo-400 hover:text-indigo-300 break-all"
                >
                  <ExternalLink class="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                  <span>{{ reference.type }} — {{ reference.url }}</span>
                </a>
              </li>
            </ul>
          </div>

          <p
            v-if="entry.advisory.published || entry.advisory.modified"
            class="mt-3 text-[11px] text-slate-500"
          >
            <span v-if="entry.advisory.published">
              Published {{ formatDate(entry.advisory.published) }}
            </span>
            <span v-if="entry.advisory.published && entry.advisory.modified"> · </span>
            <span v-if="entry.advisory.modified">
              Updated {{ formatDate(entry.advisory.modified) }}
            </span>
          </p>
        </article>
      </div>
    </div>
  </div>
</template>
