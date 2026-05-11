package config

// Config mirrors the trusttunnel_client TOML structure exactly.
type Config struct {
	Loglevel                string   `toml:"loglevel"`
	VpnMode                 string   `toml:"vpn_mode"`
	KillswitchEnabled       bool     `toml:"killswitch_enabled"`
	KillswitchAllowPorts    []int    `toml:"killswitch_allow_ports"`
	PostQuantumGroupEnabled bool     `toml:"post_quantum_group_enabled"`
	Exclusions              []string `toml:"exclusions"`
	SSLSessionCachePath     string   `toml:"ssl_session_cache_path,omitempty"`

	Endpoint Endpoint `toml:"endpoint"`
	Listener Listener `toml:"listener"`
}

type Endpoint struct {
	Hostname         string   `toml:"hostname"`
	Addresses        []string `toml:"addresses"`
	CustomSNI        string   `toml:"custom_sni"`
	HasIPv6          bool     `toml:"has_ipv6"`
	Username         string   `toml:"username"`
	Password         string   `toml:"password"`
	ClientRandom     string   `toml:"client_random"`
	SkipVerification bool     `toml:"skip_verification"`
	Certificate      string   `toml:"certificate"`
	UpstreamProtocol string   `toml:"upstream_protocol"`
	AntiDPI          bool     `toml:"anti_dpi"`
	DNSUpstreams     []string `toml:"dns_upstreams"`
}

type Listener struct {
	TUN  *TUNListener  `toml:"tun,omitempty"`
	SOCKS *SOCKSListener `toml:"socks,omitempty"`
}

type TUNListener struct {
	BoundIf        string   `toml:"bound_if"`
	IncludedRoutes []string `toml:"included_routes"`
	ExcludedRoutes []string `toml:"excluded_routes"`
	MTUSize        uint32   `toml:"mtu_size"`
	TCPRecvBufSize uint32   `toml:"tcp_recv_buf_size,omitempty"`
	TCPSendBufSize uint32   `toml:"tcp_send_buf_size,omitempty"`
	ChangeSystemDNS bool    `toml:"change_system_dns"`
	DeviceName     string   `toml:"device_name"`
	UseExisting    bool     `toml:"use_existing"`
}

type SOCKSListener struct {
	Address  string `toml:"address"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}
