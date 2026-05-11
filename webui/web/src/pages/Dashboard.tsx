import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useConnectionStore } from '@/store/connection'
import { Card, CardTitle } from '@/components/Card'
import { StatusBadge } from '@/components/Badge'
import { Button } from '@/components/Button'
import { formatUptime } from '@/lib/utils'
import { useEffect } from 'react'

function StatRow({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-white/6 last:border-0">
      <span className="text-sm text-white/50">{label}</span>
      <span className="text-sm font-mono text-white/90">{value}</span>
    </div>
  )
}

export function Dashboard() {
  const qc = useQueryClient()
  const setStatus = useConnectionStore((s) => s.setStatus)

  const { data: status, isLoading } = useQuery({
    queryKey: ['status'],
    queryFn: api.status,
    refetchInterval: 5000,
  })

  useEffect(() => {
    if (status) setStatus(status)
  }, [status, setStatus])

  const connect = useMutation({
    mutationFn: api.connect,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  })
  const disconnect = useMutation({
    mutationFn: api.disconnect,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  })

  const running = status?.running ?? false
  const badgeVariant = running ? 'connected' : 'disconnected'

  return (
    <div className="max-w-2xl mx-auto w-full py-8 px-4 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-white/40 mt-1">VPN tunnel status and controls</p>
        </div>
        <StatusBadge variant={badgeVariant} label={running ? 'Connected' : 'Disconnected'} />
      </div>

      <Card>
        <CardTitle>Connection</CardTitle>
        <StatRow label="External IP" value={status?.external_ip} />
        <StatRow label="Interface" value={status?.interface} />
        <StatRow
          label="Uptime"
          value={status?.uptime_seconds != null ? formatUptime(status.uptime_seconds) : undefined}
        />
        <StatRow label="Mode" value={status?.vpn_mode} />
        <StatRow label="PID" value={status?.pid?.toString()} />

        {!running && !isLoading && (
          <div className="mt-4 text-sm text-white/30 text-center py-3">Tunnel is not running</div>
        )}
      </Card>

      <Card>
        <CardTitle>Security</CardTitle>
        <div className="flex items-center justify-between py-2">
          <span className="text-sm text-white/50">Kill Switch</span>
          <span
            className={`text-xs font-medium px-2 py-0.5 rounded-full ${
              status?.killswitch
                ? 'bg-emerald-500/15 text-emerald-400'
                : 'bg-white/8 text-white/40'
            }`}
          >
            {status?.killswitch ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </Card>

      <div className="flex justify-center pt-2">
        {running ? (
          <Button
            variant="destructive"
            size="lg"
            loading={disconnect.isPending}
            onClick={() => disconnect.mutate()}
          >
            Disconnect
          </Button>
        ) : (
          <Button
            size="lg"
            loading={connect.isPending || isLoading}
            onClick={() => connect.mutate()}
          >
            Connect
          </Button>
        )}
      </div>

      {(connect.error || disconnect.error) && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
          {String(connect.error || disconnect.error)}
        </div>
      )}
    </div>
  )
}
