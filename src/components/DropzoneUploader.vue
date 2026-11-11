<script setup lang="ts">
import { computed, ref } from 'vue'
import { AlertCircle, FileJson, Loader2, UploadCloud, XCircle } from 'lucide-vue-next'
import { useScannerStore } from '@/stores/scannerStore'

const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024

const store = useScannerStore()
const isDragging = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const localError = ref<string | null>(null)

const progressPercent = computed(() => {
  if (store.totalCount === 0) return 0
  return Math.round((store.scannedCount / store.totalCount) * 100)
})

const resetInput = () => {
  if (fileInput.value) fileInput.value.value = ''
}

const validateFile = (file: File): string | null => {
  const isJson = file.name.toLowerCase().endsWith('.json') || file.type === 'application/json'
  if (!isJson) return 'Only .json manifest files are supported.'
  if (file.size === 0) return 'The selected file is empty.'
  if (file.size > MAX_FILE_SIZE_BYTES) return 'File is too large. The maximum size is 2 MB.'
  return null
}

const readFile = (file: File) => {
  if (store.isScanning) return
  localError.value = null

  const validationError = validateFile(file)
  if (validationError) {
    localError.value = validationError
    return
  }

  const reader = new FileReader()
  reader.onerror = () => {
    localError.value = 'The file could not be read. Please try again.'
  }
  reader.onload = (event) => {
    const content = event.target?.result as string
    store.scanFileContent(content, file.name)
  }
  reader.readAsText(file)
}

const handleDrop = (event: DragEvent) => {
  isDragging.value = false
  if (store.isScanning) return
  const file = event.dataTransfer?.files?.[0]
  if (file) readFile(file)
}

const handleFileInput = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  if (file) readFile(file)
  resetInput()
}

const openFilePicker = () => {
  if (store.isScanning) return
  fileInput.value?.click()
}

const handleKeydown = (event: KeyboardEvent) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    openFilePicker()
  }
}

const triggerSampleScan = () => {
  if (store.isScanning) return
  localError.value = null
  const sample = {
    dependencies: {
      lodash: '4.17.15',
      axios: '0.21.1',
      express: '4.16.0',
      pinia: '^2.1.7',
    },
  }
  store.scanFileContent(JSON.stringify(sample, null, 2), 'demo-manifest.json')
}
</script>

<template>
  <section class="bg-slate-900 border border-slate-800 rounded-xl p-6" aria-labelledby="upload-heading">
    <div
      class="border-2 border-dashed rounded-lg p-8 text-center transition-all"
      :class="[
        isDragging ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-700 hover:border-slate-500',
        store.isScanning ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
      ]"
      role="button"
      tabindex="0"
      :aria-disabled="store.isScanning"
      aria-label="Upload a package.json manifest"
      @dragover.prevent="isDragging = true"
      @dragleave.prevent="isDragging = false"
      @drop.prevent="handleDrop"
      @click="openFilePicker"
      @keydown="handleKeydown"
    >
      <input
        ref="fileInput"
        type="file"
        accept=".json,application/json"
        class="hidden"
        aria-hidden="true"
        tabindex="-1"
        @change="handleFileInput"
      />
      <Loader2
        v-if="store.isScanning"
        class="w-12 h-12 text-indigo-400 mx-auto mb-3 animate-spin"
        aria-hidden="true"
      />
      <UploadCloud v-else class="w-12 h-12 text-indigo-400 mx-auto mb-3" aria-hidden="true" />
      <h3 id="upload-heading" class="text-lg font-semibold text-white">
        {{ store.isScanning ? 'Scanning dependencies…' : 'Upload package.json' }}
      </h3>
      <p class="text-sm text-slate-400 mt-1">
        Drag and drop your manifest here or click to select
      </p>
      <p class="text-xs text-slate-500 mt-2">JSON manifest · up to 2 MB</p>
    </div>

    <div v-if="store.isScanning" class="mt-4">
      <div class="flex items-center justify-between text-xs text-slate-400 mb-1.5">
        <span>Checking {{ store.scannedCount }} of {{ store.totalCount }} dependencies</span>
        <span class="font-mono">{{ progressPercent }}%</span>
      </div>
      <div
        class="w-full h-2 rounded-full bg-slate-800 overflow-hidden"
        role="progressbar"
        :aria-valuenow="progressPercent"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-label="`Scan progress: ${progressPercent}%`"
      >
        <div
          class="h-full bg-indigo-500 transition-all duration-300"
          :style="{ width: `${progressPercent}%` }"
        />
      </div>
      <button
        type="button"
        class="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold text-rose-400 hover:text-rose-300"
        @click="store.cancelScan()"
      >
        <XCircle class="w-3.5 h-3.5" aria-hidden="true" /> Cancel scan
      </button>
    </div>

    <div
      v-if="localError || store.errorMessage"
      role="alert"
      class="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-center gap-2 text-rose-400 text-xs"
    >
      <AlertCircle class="w-4 h-4 shrink-0" aria-hidden="true" />
      <span>{{ localError || store.errorMessage }}</span>
    </div>

    <div
      v-else-if="store.isComplete && !store.hasFailures"
      role="status"
      class="mt-4 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center gap-2 text-emerald-400 text-xs"
    >
      <FileJson class="w-4 h-4 shrink-0" aria-hidden="true" />
      <span>
        Scanned {{ store.metrics.total }} dependencies
        {{ store.sourceName ? `from ${store.sourceName}` : '' }}.
      </span>
    </div>

    <div class="mt-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs text-slate-400">
      <span>No package.json file ready?</span>
      <button
        type="button"
        :disabled="store.isScanning"
        class="text-indigo-400 hover:text-indigo-300 font-medium underline underline-offset-4 disabled:opacity-50 disabled:cursor-not-allowed text-left"
        @click="triggerSampleScan"
      >
        Load demo vulnerable manifest
      </button>
    </div>
  </section>
</template>
