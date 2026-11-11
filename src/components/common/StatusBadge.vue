<script setup lang="ts">
import { computed } from 'vue'
import { AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-vue-next'
import type { ScanStatus } from '@/types/vulnerability'

const props = defineProps<{
  status: ScanStatus
}>()

const config = computed(() => {
  switch (props.status) {
    case 'vulnerable':
      return {
        label: 'Vulnerable',
        icon: AlertTriangle,
        classes: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      }
    case 'error':
      return {
        label: 'Scan failed',
        icon: ShieldAlert,
        classes: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      }
    default:
      return {
        label: 'Clean',
        icon: ShieldCheck,
        classes: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      }
  }
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border"
    :class="config.classes"
  >
    <component :is="config.icon" class="w-3.5 h-3.5" aria-hidden="true" />
    {{ config.label }}
  </span>
</template>
