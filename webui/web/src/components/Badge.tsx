import { cn } from '@/lib/utils'

type Variant = 'connected' | 'disconnected' | 'connecting'

const variants: Record<Variant, string> = {
  connected: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  disconnected: 'bg-white/8 text-white/40 border-white/10',
  connecting: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
}

const dots: Record<Variant, string> = {
  connected: 'bg-emerald-400 animate-pulse',
  disconnected: 'bg-white/30',
  connecting: 'bg-sky-400 animate-ping',
}

interface BadgeProps {
  variant: Variant
  label: string
}

export function StatusBadge({ variant, label }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium',
        variants[variant]
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', dots[variant])} />
      {label}
    </span>
  )
}
