import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api } from '@/api/client'
import { Card, CardTitle } from '@/components/Card'
import { Button } from '@/components/Button'

const EXAMPLES = ['example.com', '*.example.com', '192.168.0.0/16', '10.0.0.1:8080', '*:443']

export function Exclusions() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['config'], queryFn: api.getConfig })
  const [items, setItems] = useState<string[]>([])
  const [input, setInput] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (data) setItems(data.exclusions ?? [])
  }, [data])

  const save = useMutation({
    mutationFn: async () => {
      if (!data) return
      await api.putConfig({ ...data, exclusions: items })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const add = () => {
    const v = input.trim()
    if (v && !items.includes(v)) {
      setItems((prev) => [...prev, v])
    }
    setInput('')
  }

  const remove = (idx: number) => setItems((prev) => prev.filter((_, i) => i !== idx))

  return (
    <div className="max-w-2xl mx-auto w-full py-8 px-4 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Exclusions</h1>
          <p className="text-sm text-white/40 mt-1">
            Domains and IPs routed differently based on VPN mode
          </p>
        </div>
        <Button loading={save.isPending} onClick={() => save.mutate()}>
          {saved ? '✓ Saved' : 'Save'}
        </Button>
      </div>

      <Card>
        <CardTitle>Add exclusion</CardTitle>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && add()}
            placeholder="domain, IP, CIDR or wildcard…"
            className="flex-1 rounded-lg bg-white/6 border border-white/10 px-3 py-2 text-sm text-white placeholder:text-white/25 outline-none focus:border-sky-500/50"
          />
          <Button onClick={add} disabled={!input.trim()}>Add</Button>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => setInput(ex)}
              className="text-xs px-2 py-1 rounded-md bg-white/6 text-white/40 hover:text-white/70 font-mono transition-colors"
            >
              {ex}
            </button>
          ))}
        </div>
      </Card>

      <Card>
        <CardTitle>Current exclusions ({items.length})</CardTitle>
        {items.length === 0 ? (
          <div className="text-sm text-white/30 text-center py-6">No exclusions configured</div>
        ) : (
          <ul className="flex flex-col gap-1">
            {items.map((item, i) => (
              <li
                key={i}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/4 hover:bg-white/6 transition-colors group"
              >
                <span className="text-sm font-mono text-white/80">{item}</span>
                <button
                  onClick={() => remove(i)}
                  className="text-white/20 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100 text-lg leading-none"
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
