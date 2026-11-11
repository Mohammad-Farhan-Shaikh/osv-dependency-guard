<script setup lang="ts">
import { AlertTriangle } from 'lucide-vue-next'
import type { UnsupportedDependency } from '@/types/vulnerability'

defineProps<{
  dependencies: UnsupportedDependency[]
}>()
</script>

<template>
  <section
    class="mt-6 bg-amber-500/5 border border-amber-500/20 rounded-xl p-5"
    aria-labelledby="unsupported-heading"
  >
    <div class="flex items-start gap-3">
      <AlertTriangle class="w-5 h-5 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
      <div class="w-full">
        <h2 id="unsupported-heading" class="text-sm font-semibold text-amber-300">
          {{ dependencies.length }}
          {{ dependencies.length === 1 ? 'dependency' : 'dependencies' }} could not be scanned
        </h2>
        <p class="text-xs text-amber-200/70 mt-1">
          These entries are not npm registry versions, so they were skipped. They are not counted
          as clean.
        </p>
        <ul class="mt-3 space-y-2">
          <li
            v-for="item in dependencies"
            :key="`${item.name}|${item.rawVersion}|${item.reason}`"
            class="text-xs"
          >
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-mono font-semibold text-white">{{ item.name }}</span>
              <code class="text-amber-300/90 bg-amber-500/10 px-1.5 py-0.5 rounded">{{
                item.rawVersion
              }}</code>
              <span class="text-[10px] uppercase tracking-wide text-amber-400/80">{{
                item.reason
              }}</span>
            </div>
            <p class="text-amber-200/60 mt-0.5">{{ item.note }}</p>
          </li>
        </ul>
      </div>
    </div>
  </section>
</template>
