<script setup lang="ts">
defineProps<{
  title: string
  value: string | number
  subtitle?: string
  variant?: 'default' | 'danger' | 'success' | 'warning'
}>()
</script>

<template>
  <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
    <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">{{ title }}</span>
    <div
      class="text-3xl font-bold mt-2 font-mono"
      :class="{
        'text-rose-500': variant === 'danger',
        'text-emerald-400': variant === 'success',
        'text-amber-400': variant === 'warning',
        'text-white': !variant || variant === 'default',
      }"
    >
      {{ value }}
    </div>
    <p v-if="subtitle" class="text-xs text-slate-400 mt-1">{{ subtitle }}</p>
  </div>
</template>
