import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useConnectionStore } from '@/store/connection'
import { StatusBadge } from './Badge'

const navItems = [
  { to: '/', label: 'Dashboard', icon: '⬡' },
  { to: '/config', label: 'Config', icon: '⚙' },
  { to: '/exclusions', label: 'Exclusions', icon: '⊘' },
  { to: '/dns', label: 'DNS', icon: '◎' },
  { to: '/logs', label: 'Logs', icon: '≡' },
]

export function Sidebar() {
  const status = useConnectionStore((s) => s.status)
  const variant = status?.running ? 'connected' : 'disconnected'
  const label = status?.running ? 'Connected' : 'Disconnected'

  return (
    <aside className="flex flex-col w-56 shrink-0 border-r border-white/8 py-6 px-4 gap-6">
      <div className="px-2">
        <div className="text-base font-bold text-white tracking-tight">TrustTunnel</div>
        <div className="text-xs text-white/40 mt-0.5">WebUI</div>
      </div>

      <nav className="flex flex-col gap-1">
        {navItems.map(({ to, label: navLabel, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-xl text-sm transition-colors',
                isActive
                  ? 'bg-sky-500/15 text-sky-400 font-medium'
                  : 'text-white/50 hover:text-white hover:bg-white/6'
              )
            }
          >
            <span className="text-base leading-none">{icon}</span>
            {navLabel}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto px-2">
        <StatusBadge variant={variant} label={label} />
        {status?.external_ip && (
          <div className="mt-2 text-xs text-white/30 font-mono">{status.external_ip}</div>
        )}
      </div>
    </aside>
  )
}
