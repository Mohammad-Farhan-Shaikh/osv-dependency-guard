<script setup lang="ts">
import { useScannerStore } from '@/stores/scannerStore'
import DropzoneUploader from '@/components/DropzoneUploader.vue'
import VulnerabilityTable from '@/components/VulnerabilityTable.vue'
import AdvisoryDrawer from '@/components/AdvisoryDrawer.vue'
import UnsupportedDependencies from '@/components/UnsupportedDependencies.vue'
import ExportToolbar from '@/components/ExportToolbar.vue'
import MetricCard from '@/components/common/MetricCard.vue'
import { AlertTriangle, Ban, CheckCircle2, RotateCcw, Shield } from 'lucide-vue-next'

const store = useScannerStore()
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100">
    <a
      href="#main-content"
      class="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-indigo-600 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-white"
    >
      Skip to main content
    </a>
    <div class="max-w-6xl mx-auto px-4 py-10">
      <header
        class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between pb-8 border-b border-slate-800 mb-8"
      >
        <div class="flex items-center gap-3">
          <div
            class="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/30"
          >
            <Shield class="w-6 h-6 text-white" aria-hidden="true" />
          </div>
          <div>
            <h1 class="text-xl font-bold text-white tracking-tight">DepGuard Security Engine</h1>
            <p class="text-xs text-slate-400">Automated Dependency Auditing via Google OSV API</p>
          </div>
        </div>
        <div>
          <span
            class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
          >
            Live OSV Feed Active
          </span>
        </div>
      </header>

      <main id="main-content" tabindex="-1">
        <DropzoneUploader />

        <p v-if="store.manifestWarnings.length > 0" class="mt-3 text-xs text-slate-400">
          {{ store.manifestWarnings.join(' ') }}
        </p>

      <UnsupportedDependencies
        v-if="store.unsupportedDependencies.length > 0"
        :dependencies="store.unsupportedDependencies"
      />

      <div v-if="!store.isScanning && store.scanResults.length > 0" class="mt-8">
        <div
          v-if="store.isCancelled"
          role="status"
          class="mb-6 p-4 rounded-xl border flex items-start gap-3 bg-amber-500/10 border-amber-500/20 text-amber-300"
        >
          <Ban class="w-5 h-5 shrink-0 mt-0.5" aria-hidden="true" />
          <div class="text-sm">
            <p class="font-semibold">Scan cancelled</p>
            <p class="text-xs text-amber-200/70 mt-0.5">
              Showing partial results — {{ store.metrics.total }} of {{ store.totalCount }}
              dependencies were checked.
            </p>
          </div>
        </div>

        <div
          v-else-if="store.hasFailures"
          role="status"
          class="mb-6 p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 bg-amber-500/10 border-amber-500/20 text-amber-300"
        >
          <div class="flex items-start gap-3">
            <AlertTriangle class="w-5 h-5 shrink-0 mt-0.5" aria-hidden="true" />
            <div class="text-sm">
              <p class="font-semibold">
                {{ store.metrics.errorCount }} dependencies could not be scanned
              </p>
              <p class="text-xs text-amber-200/70 mt-0.5">
                These results are incomplete. Failed checks are never counted as clean.
              </p>
            </div>
          </div>
          <button
            type="button"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 transition shrink-0"
            @click="store.retryFailedScans()"
          >
            <RotateCcw class="w-3.5 h-3.5" aria-hidden="true" /> Retry failed
          </button>
        </div>

        <div
          v-else-if="store.hasVulnerabilities"
          role="status"
          class="mb-6 p-4 rounded-xl border flex items-start gap-3 bg-rose-500/10 border-rose-500/20 text-rose-300"
        >
          <AlertTriangle class="w-5 h-5 shrink-0 mt-0.5" aria-hidden="true" />
          <div class="text-sm">
            <p class="font-semibold">
              Vulnerabilities found in {{ store.metrics.vulnerableCount }} of
              {{ store.metrics.total }} dependencies
            </p>
            <p class="text-xs text-rose-200/70 mt-0.5">
              Open a package's advisories for details and fixed versions.
            </p>
          </div>
        </div>

        <div
          v-else
          role="status"
          class="mb-6 p-4 rounded-xl border flex items-start gap-3 bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
        >
          <CheckCircle2 class="w-5 h-5 shrink-0 mt-0.5" aria-hidden="true" />
          <div class="text-sm">
            <p class="font-semibold">No known vulnerabilities found</p>
            <p class="text-xs text-emerald-200/70 mt-0.5">
              All {{ store.metrics.total }} dependencies scanned cleanly.
            </p>
          </div>
        </div>

        <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
          <MetricCard
            title="Total Scanned"
            :value="store.metrics.total"
            subtitle="Packages parsed"
          />
          <MetricCard
            title="Vulnerable"
            :value="store.metrics.vulnerableCount"
            variant="danger"
            subtitle="Action needed"
          />
          <MetricCard
            title="Clean"
            :value="store.metrics.cleanCount"
            variant="success"
            subtitle="No advisories matched"
          />
          <MetricCard
            title="Failed"
            :value="store.metrics.errorCount"
            variant="warning"
            subtitle="Could not be checked"
          />
          <MetricCard
            title="Health Score"
            :value="`${store.metrics.healthScore}%`"
            :variant="
              store.metrics.healthScore >= 80
                ? 'success'
                : store.metrics.healthScore >= 50
                  ? 'warning'
                  : 'danger'
            "
            :subtitle="
              store.metrics.errorCount > 0 ? 'Partial — some scans failed' : 'Overall manifest rating'
            "
          />
        </div>

        <div class="mb-6">
          <ExportToolbar />
        </div>

        <VulnerabilityTable />
      </div>
      </main>

      <footer class="mt-10 pt-6 border-t border-slate-800 text-xs text-slate-400">
        <p>
          DepGuard runs entirely in your browser. Your manifest never leaves this device, and no API
          key is required.
        </p>
      </footer>

      <AdvisoryDrawer />
    </div>
  </div>
</template>
