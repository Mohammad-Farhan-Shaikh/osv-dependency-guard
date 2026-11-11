import type { SeverityLevel, VulnerabilityAdvisory } from '@/types/vulnerability'

export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0,
}

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MODERATE: 'Moderate',
  LOW: 'Low',
  UNKNOWN: 'Unknown',
}

export const SEVERITY_TEXT_CLASS: Record<SeverityLevel, string> = {
  CRITICAL: 'text-rose-500',
  HIGH: 'text-orange-400',
  MODERATE: 'text-amber-400',
  LOW: 'text-sky-400',
  UNKNOWN: 'text-slate-400',
}

export function getMaxSeverity(advisories: VulnerabilityAdvisory[]): SeverityLevel | null {
  if (advisories.length === 0) return null

  let max: SeverityLevel = 'UNKNOWN'
  for (const advisory of advisories) {
    if (SEVERITY_RANK[advisory.severity] > SEVERITY_RANK[max]) {
      max = advisory.severity
    }
  }
  return max
}
