package api

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/neshumov/trusttunnel-webui/internal/config"
)

type statusResponse struct {
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	UptimeSec int64  `json:"uptime_seconds,omitempty"`
	Interface string `json:"interface,omitempty"`
	ExternalIP string `json:"external_ip,omitempty"`
	VpnMode    string `json:"vpn_mode,omitempty"`
	Killswitch bool   `json:"killswitch"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	proc := s.manager.Status()

	resp := statusResponse{
		Running:   proc.Running,
		PID:       proc.PID,
		UptimeSec: proc.UptimeSec,
	}

	if cfg, err := config.Read(s.configPath); err == nil {
		resp.VpnMode = cfg.VpnMode
		resp.Killswitch = cfg.KillswitchEnabled
	}

	if proc.Running {
		resp.Interface = detectTunInterface()
		resp.ExternalIP = fetchExternalIP()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func detectTunInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		// macOS TUN interfaces created by TrustTunnel start with "utun"
		if len(iface.Name) >= 4 && iface.Name[:4] == "utun" {
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				return iface.Name
			}
		}
	}
	return ""
}

func fetchExternalIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
