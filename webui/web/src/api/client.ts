export interface Status {
  running: boolean
  pid?: number
  uptime_seconds?: number
  interface?: string
  external_ip?: string
  vpn_mode?: string
  killswitch: boolean
}

export interface TUNListener {
  bound_if: string
  included_routes: string[]
  excluded_routes: string[]
  mtu_size: number
  tcp_recv_buf_size?: number
  tcp_send_buf_size?: number
  change_system_dns: boolean
  device_name: string
  use_existing: boolean
}

export interface SOCKSListener {
  address: string
  username: string
  password: string
}

export interface Endpoint {
  hostname: string
  addresses: string[]
  custom_sni: string
  has_ipv6: boolean
  username: string
  password: string
  client_random: string
  skip_verification: boolean
  certificate: string
  upstream_protocol: string
  anti_dpi: boolean
  dns_upstreams: string[]
}

export interface Config {
  loglevel: string
  vpn_mode: string
  killswitch_enabled: boolean
  killswitch_allow_ports: number[]
  post_quantum_group_enabled: boolean
  exclusions: string[]
  endpoint: Endpoint
  listener: {
    tun?: TUNListener
    socks?: SOCKSListener
  }
}

const BASE = '/api'

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, opts)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  status: () => req<Status>('/status'),
  getConfig: () => req<Config>('/config'),
  putConfig: (cfg: Config) =>
    req<void>('/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    }),
  connect: () => req<{ status: string }>('/connect', { method: 'POST' }),
  disconnect: () => req<{ status: string }>('/disconnect', { method: 'POST' }),
}
