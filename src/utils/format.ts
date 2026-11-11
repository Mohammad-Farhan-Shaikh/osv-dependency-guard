import type { AffectedRange } from '@/types/vulnerability'

export function formatAffectedRange(range: AffectedRange): string {
  if (range.introduced && range.fixed) return `>= ${range.introduced}, < ${range.fixed}`
  if (range.introduced) return `>= ${range.introduced}`
  if (range.fixed) return `< ${range.fixed}`
  return 'Unknown range'
}
