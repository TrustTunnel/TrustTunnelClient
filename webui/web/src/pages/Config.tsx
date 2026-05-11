import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api, type Config } from '@/api/client'
import { Card, CardTitle } from '@/components/Card'
import { Toggle } from '@/components/Toggle'
import { Button } from '@/components/Button'

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5 py-3 border-b border-white/6 last:border-0">
      <div className="flex items-baseline justify-between">
        <label className="text-sm text-white/70">{label}</label>
        {hint && <span className="text-xs text-white/30">{hint}</span>}
      </div>
      {children}
    </div>
  )
}

export function Config() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ['config'], queryFn: api.getConfig })
  const [cfg, setCfg] = useState<Config | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (data && !cfg) setCfg(data)
  }, [data])

  const save = useMutation({
    mutationFn: (c: Config) => api.putConfig(c),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  if (isLoading || !cfg) {
    return <div className="p-8 text-white/40">Loading config…</div>
  }

  const set = <K extends keyof Config>(key: K, value: Config[K]) =>
    setCfg((c) => c ? { ...c, [key]: value } : c)

  const setEndpoint = <K extends keyof Config['endpoint']>(key: K, value: Config['endpoint'][K]) =>
    setCfg((c) => c ? { ...c, endpoint: { ...c.endpoint, [key]: value } } : c)

  const setTun = <K extends keyof NonNullable<Config['listener']['tun']>>(
    key: K, value: NonNullable<Config['listener']['tun']>[K]
  ) =>
    setCfg((c) =>
      c ? { ...c, listener: { ...c.listener, tun: c.listener.tun ? { ...c.listener.tun, [key]: value } : undefined } } : c
    )

  return (
    <div className="max-w-2xl mx-auto w-full py-8 px-4 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Config</h1>
          <p className="text-sm text-white/40 mt-1">Edit trusttunnel_client.toml</p>
        </div>
        <Button
          loading={save.isPending}
          onClick={() => cfg && save.mutate(cfg)}
        >
          {saved ? '✓ Saved' : 'Save'}
        </Button>
      </div>

      <Card>
        <CardTitle>General</CardTitle>
        <Field label="Log level" hint="error | warn | info | debug | trace">
          <select
            value={cfg.loglevel}
            onChange={(e) => set('loglevel', e.target.value)}
            className="w-full rounded-lg bg-white/6 border border-white/10 px-3 py-2 text-sm text-white outline-none"
          >
            {['error', 'warn', 'info', 'debug', 'trace'].map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </Field>
        <Field label="VPN mode">
          <div className="flex gap-3">
            {(['general', 'selective'] as const).map((m) => (
              <button
                key={m}
                onClick={() => set('vpn_mode', m)}
                className={`flex-1 py-2 rounded-lg border text-sm transition-colors ${
                  cfg.vpn_mode === m
                    ? 'border-sky-500 bg-sky-500/15 text-sky-400'
                    : 'border-white/10 text-white/50 hover:border-white/20'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Kill switch">
          <Toggle
            checked={cfg.killswitch_enabled}
            onChange={(v) => set('killswitch_enabled', v)}
          />
        </Field>
        <Field label="Post-quantum key exchange">
          <Toggle
            checked={cfg.post_quantum_group_enabled}
            onChange={(v) => set('post_quantum_group_enabled', v)}
          />
        </Field>
      </Card>

      <Card>
        <CardTitle>Endpoint</CardTitle>
        <Field label="Hostname">
          <input
            value={cfg.endpoint.hostname}
            onChange={(e) => setEndpoint('hostname', e.target.value)}
            className="w-full"
            placeholder="nl.example.com"
          />
        </Field>
        <Field label="Addresses" hint="one per line (host:port)">
          <textarea
            rows={3}
            value={cfg.endpoint.addresses.join('\n')}
            onChange={(e) => setEndpoint('addresses', e.target.value.split('\n').filter(Boolean))}
            className="w-full font-mono text-xs resize-none"
          />
        </Field>
        <Field label="Username">
          <input value={cfg.endpoint.username} onChange={(e) => setEndpoint('username', e.target.value)} className="w-full" />
        </Field>
        <Field label="Password">
          <input type="password" value={cfg.endpoint.password} onChange={(e) => setEndpoint('password', e.target.value)} className="w-full" />
        </Field>
        <Field label="Protocol">
          <div className="flex gap-3">
            {(['http2', 'http3', 'auto'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setEndpoint('upstream_protocol', p)}
                className={`flex-1 py-2 rounded-lg border text-sm transition-colors ${
                  cfg.endpoint.upstream_protocol === p
                    ? 'border-sky-500 bg-sky-500/15 text-sky-400'
                    : 'border-white/10 text-white/50 hover:border-white/20'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Anti-DPI">
          <Toggle checked={cfg.endpoint.anti_dpi} onChange={(v) => setEndpoint('anti_dpi', v)} />
        </Field>
        <Field label="IPv6 support">
          <Toggle checked={cfg.endpoint.has_ipv6} onChange={(v) => setEndpoint('has_ipv6', v)} />
        </Field>
        <Field label="Skip TLS verification">
          <Toggle checked={cfg.endpoint.skip_verification} onChange={(v) => setEndpoint('skip_verification', v)} />
        </Field>
      </Card>

      {cfg.listener.tun && (
        <Card>
          <CardTitle>TUN Interface</CardTitle>
          <Field label="MTU size">
            <input
              type="number"
              value={cfg.listener.tun.mtu_size}
              onChange={(e) => setTun('mtu_size', parseInt(e.target.value) || 1280)}
              className="w-full"
            />
          </Field>
          <Field label="Device name" hint="leave blank for auto">
            <input value={cfg.listener.tun.device_name} onChange={(e) => setTun('device_name', e.target.value)} className="w-full" />
          </Field>
          <Field label="Change system DNS">
            <Toggle checked={cfg.listener.tun.change_system_dns} onChange={(v) => setTun('change_system_dns', v)} />
          </Field>
        </Card>
      )}

      {cfg.listener.socks && (
        <Card>
          <CardTitle>SOCKS5 Listener</CardTitle>
          <Field label="Bind address">
            <input
              value={cfg.listener.socks.address}
              onChange={(e) =>
                setCfg((c) => c ? { ...c, listener: { ...c.listener, socks: { ...c.listener.socks!, address: e.target.value } } } : c)
              }
              className="w-full font-mono text-sm"
            />
          </Field>
        </Card>
      )}

      {save.error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
          {String(save.error)}
        </div>
      )}
    </div>
  )
}
