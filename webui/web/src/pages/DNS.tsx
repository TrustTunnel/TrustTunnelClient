import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api } from '@/api/client'
import { Card, CardTitle } from '@/components/Card'
import { Button } from '@/components/Button'

type DNSType = 'plain' | 'tcp' | 'tls' | 'https' | 'quic' | 'sdns' | 'unknown'

function classifyDNS(s: string): DNSType {
  if (s.startsWith('sdns://')) return 'sdns'
  if (s.startsWith('https://')) return 'https'
  if (s.startsWith('quic://')) return 'quic'
  if (s.startsWith('tls://')) return 'tls'
  if (s.startsWith('tcp://')) return 'tcp'
  if (/^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(s) || /^\[.+\](:\d+)?$/.test(s)) return 'plain'
  return 'unknown'
}

const typeColors: Record<DNSType, string> = {
  plain: 'text-white/50 bg-white/8',
  tcp: 'text-blue-400 bg-blue-500/10',
  tls: 'text-sky-400 bg-sky-500/10',
  https: 'text-violet-400 bg-violet-500/10',
  quic: 'text-emerald-400 bg-emerald-500/10',
  sdns: 'text-amber-400 bg-amber-500/10',
  unknown: 'text-white/30 bg-white/5',
}

const typeLabels: Record<DNSType, string> = {
  plain: 'DNS',
  tcp: 'TCP',
  tls: 'DoT',
  https: 'DoH',
  quic: 'DoQ',
  sdns: 'Stamp',
  unknown: '?',
}

const PRESETS = [
  { label: 'AdGuard DNS', value: 'https://dns.adguard.com/dns-query' },
  { label: 'Cloudflare', value: 'https://cloudflare-dns.com/dns-query' },
  { label: '1.1.1.1', value: '1.1.1.1:53' },
  { label: '8.8.8.8', value: '8.8.8.8:53' },
]

export function DNS() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['config'], queryFn: api.getConfig })
  const [items, setItems] = useState<string[]>([])
  const [input, setInput] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (data) setItems(data.endpoint.dns_upstreams ?? [])
  }, [data])

  const save = useMutation({
    mutationFn: async () => {
      if (!data) return
      await api.putConfig({ ...data, endpoint: { ...data.endpoint, dns_upstreams: items } })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const add = (value?: string) => {
    const v = (value ?? input).trim()
    if (v && !items.includes(v)) setItems((prev) => [...prev, v])
    if (!value) setInput('')
  }

  return (
    <div className="max-w-2xl mx-auto w-full py-8 px-4 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">DNS Upstreams</h1>
          <p className="text-sm text-white/40 mt-1">Resolvers used through the tunnel</p>
        </div>
        <Button loading={save.isPending} onClick={() => save.mutate()}>
          {saved ? '✓ Saved' : 'Save'}
        </Button>
      </div>

      <Card>
        <CardTitle>Add upstream</CardTitle>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && add()}
            placeholder="8.8.8.8:53 or https://… or tls://… or sdns://…"
            className="flex-1 rounded-lg bg-white/6 border border-white/10 px-3 py-2 text-sm font-mono text-white placeholder:text-white/25 outline-none focus:border-sky-500/50"
          />
          <Button onClick={() => add()} disabled={!input.trim()}>Add</Button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <button
              key={p.value}
              onClick={() => add(p.value)}
              className="text-xs px-2.5 py-1.5 rounded-lg border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </Card>

      <Card>
        <CardTitle>Configured upstreams ({items.length})</CardTitle>
        {items.length === 0 ? (
          <div className="text-sm text-white/30 text-center py-6">
            No DNS upstreams — using system default
          </div>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {items.map((item, i) => {
              const type = classifyDNS(item)
              return (
                <li
                  key={i}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-white/4 hover:bg-white/6 transition-colors group"
                >
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${typeColors[type]}`}>
                    {typeLabels[type]}
                  </span>
                  <span className="flex-1 text-sm font-mono text-white/80 truncate">{item}</span>
                  <button
                    onClick={() => setItems((prev) => prev.filter((_, j) => j !== i))}
                    className="text-white/20 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100 text-lg leading-none"
                  >
                    ×
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </Card>
    </div>
  )
}
