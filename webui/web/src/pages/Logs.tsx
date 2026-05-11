import { useEffect, useRef, useState } from 'react'
import { Card } from '@/components/Card'
import { Button } from '@/components/Button'
import { cn } from '@/lib/utils'

type Level = 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'default'

function classifyLine(line: string): Level {
  const l = line.toLowerCase()
  if (l.includes('[error]') || l.includes('error:')) return 'error'
  if (l.includes('[warn]') || l.includes('warning')) return 'warn'
  if (l.includes('[debug]')) return 'debug'
  if (l.includes('[trace]')) return 'trace'
  if (l.includes('[info]')) return 'info'
  return 'default'
}

const levelStyle: Record<Level, string> = {
  error: 'text-red-400',
  warn: 'text-amber-400',
  info: 'text-sky-400',
  debug: 'text-white/40',
  trace: 'text-white/25',
  default: 'text-white/70',
}

export function Logs() {
  const [lines, setLines] = useState<string[]>([])
  const [paused, setPaused] = useState(false)
  const [connected, setConnected] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const esRef = useRef<EventSource | null>(null)
  const pausedRef = useRef(paused)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    const es = new EventSource('/api/logs')
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (e) => {
      if (!pausedRef.current) {
        setLines((prev) => [...prev.slice(-2000), e.data])
      }
    }

    return () => es.close()
  }, [])

  useEffect(() => {
    if (!paused) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, paused])

  return (
    <div className="flex flex-col h-full py-8 px-4 gap-4 max-w-4xl mx-auto w-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Logs</h1>
          <p className="text-sm text-white/40 mt-1">
            Live output from trusttunnel_client
            <span
              className={cn(
                'ml-2 inline-block h-1.5 w-1.5 rounded-full',
                connected ? 'bg-emerald-400 animate-pulse' : 'bg-white/20'
              )}
            />
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setPaused((p) => !p)}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setLines([])}>
            Clear
          </Button>
        </div>
      </div>

      <Card className="flex-1 overflow-hidden p-0">
        <div
          className="h-full overflow-y-auto p-4 font-mono text-xs leading-relaxed"
          onScroll={(e) => {
            const el = e.currentTarget
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
            if (atBottom) setPaused(false)
            else setPaused(true)
          }}
        >
          {lines.length === 0 ? (
            <div className="text-white/20 text-center py-12">
              {connected ? 'Waiting for log output…' : 'Not connected — is the daemon running?'}
            </div>
          ) : (
            lines.map((line, i) => (
              <div key={i} className={cn('whitespace-pre-wrap break-all', levelStyle[classifyLine(line)])}>
                {line}
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </Card>
    </div>
  )
}
