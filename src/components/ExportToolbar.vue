<script setup lang="ts">
import { FileJson, FileSpreadsheet, FileText } from 'lucide-vue-next'
import { useScannerStore } from '@/stores/scannerStore'
import {
  buildCsvReport,
  buildExportFilename,
  buildJsonReport,
  buildMarkdownReport,
  type ExportSnapshot,
} from '@/utils/exporters'
import { downloadTextFile } from '@/utils/download'

const store = useScannerStore()

function snapshot(): ExportSnapshot {
  return {
    sourceName: store.sourceName,
    metrics: store.metrics,
    results: store.scanResults,
    unsupported: store.unsupportedDependencies,
    warnings: store.manifestWarnings,
    generatedAt: new Date(),
  }
}

function exportJson() {
  const data = snapshot()
  downloadTextFile(
    buildExportFilename('json', data.sourceName, data.generatedAt),
    buildJsonReport(data),
    'application/json',
  )
}

function exportCsv() {
  const data = snapshot()
  downloadTextFile(
    buildExportFilename('csv', data.sourceName, data.generatedAt),
    `\uFEFF${buildCsvReport(data)}`,
    'text/csv',
  )
}

function downloadReport() {
  const data = snapshot()
  downloadTextFile(
    buildExportFilename('md', data.sourceName, data.generatedAt),
    buildMarkdownReport(data),
    'text/markdown',
  )
}
</script>

<template>
  <section
    class="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
    aria-labelledby="export-heading"
  >
    <div>
      <h2 id="export-heading" class="text-sm font-semibold text-white">Export results</h2>
      <p class="text-xs text-slate-400 mt-0.5">
        Download the current scan for sharing, CI evidence or archiving.
      </p>
    </div>
    <div class="flex flex-wrap gap-2">
      <button
        type="button"
        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
        @click="exportJson"
      >
        <FileJson class="w-3.5 h-3.5" aria-hidden="true" /> Export JSON
      </button>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
        @click="exportCsv"
      >
        <FileSpreadsheet class="w-3.5 h-3.5" aria-hidden="true" /> Export CSV
      </button>
      <button
        type="button"
        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition focus:outline-none focus:ring-2 focus:ring-indigo-400"
        @click="downloadReport"
      >
        <FileText class="w-3.5 h-3.5" aria-hidden="true" /> Download report
      </button>
    </div>
  </section>
</template>
