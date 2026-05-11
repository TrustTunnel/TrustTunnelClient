package process

import (
	"io"
	"os/exec"
	"sync"
	"time"
)

type Manager struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	startedAt  time.Time
	logWriter  io.Writer
	clientPath string
	configPath string
}

func New(clientPath, configPath string, logWriter io.Writer) *Manager {
	return &Manager{
		clientPath: clientPath,
		configPath: configPath,
		logWriter:  logWriter,
	}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.ProcessState == nil {
		return nil // already running
	}

	m.cmd = exec.Command(m.clientPath, "--config", m.configPath)
	m.cmd.Stdout = m.logWriter
	m.cmd.Stderr = m.logWriter
	m.startedAt = time.Now()
	return m.cmd.Start()
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	return m.cmd.Process.Kill()
}

type Status struct {
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	UptimeSec int64  `json:"uptime_seconds,omitempty"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil || m.cmd.Process == nil || m.cmd.ProcessState != nil {
		return Status{Running: false}
	}
	return Status{
		Running:   true,
		PID:       m.cmd.Process.Pid,
		UptimeSec: int64(time.Since(m.startedAt).Seconds()),
	}
}
