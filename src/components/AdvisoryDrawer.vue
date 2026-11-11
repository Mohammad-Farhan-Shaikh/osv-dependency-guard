<script setup lang="ts">
import { useScannerStore } from '@/stores/scannerStore'
import { X, ShieldAlert } from 'lucide-vue-next'

const store = useScannerStore()
</script>

<template>
  <div
    v-if="store.selectedAdvisory"
    class="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end"
    @click.self="store.closeAdvisory"
  >
    <div class="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full p-6 overflow-y-auto">
      <div class="flex items-center justify-between pb-4 border-b border-slate-800">
        <div class="flex items-center gap-3">
          <ShieldAlert class="w-6 h-6 text-rose-500" />
          <h2 class="text-lg font-bold text-white font-mono">{{ store.selectedAdvisory.pkgName }}</h2>
        </div>
        <button @click="store.closeAdvisory" class="p-1 rounded-lg text-slate-400 hover:bg-slate-800 cursor-pointer">
          <X class="w-5 h-5" />
        </button>
      </div>

      <div class="mt-6 space-y-4">
        <div
          v-for="adv in store.selectedAdvisory.advisories"
          :key="adv.id"
          class="bg-slate-950 border border-slate-800 rounded-lg p-5"
        >
          <div class="flex items-center justify-between">
            <span class="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">{{ adv.id }}</span>
            <span class="text-xs font-semibold text-rose-400 uppercase tracking-wide">{{ adv.severity }}</span>
          </div>

          <h4 class="text-sm font-semibold text-white mt-3">{{ adv.summary }}</h4>
          <p class="text-xs text-slate-400 mt-2 leading-relaxed whitespace-pre-wrap">{{ adv.details }}</p>

          <div v-if="adv.fixedVersion" class="mt-4 p-3 bg-emerald-950/40 border border-emerald-800/40 rounded text-xs text-emerald-300">
            Recommended Fix: Upgrade to version <span class="font-mono font-bold">{{ adv.fixedVersion }}</span> or higher.
          </div>
        </div>
      </div>
    </div>
  </div>
</template>