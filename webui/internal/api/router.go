package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/neshumov/trusttunnel-webui/internal/logs"
	"github.com/neshumov/trusttunnel-webui/internal/process"
)

type Server struct {
	configPath string
	clientPath string
	manager    *process.Manager
	broker     *logs.Broker
}

func NewServer(clientPath, configPath string, manager *process.Manager, broker *logs.Broker) *Server {
	return &Server{
		clientPath: clientPath,
		configPath: configPath,
		manager:    manager,
		broker:     broker,
	}
}

func (s *Server) Handler() http.Handler {
	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/status", s.handleStatus).Methods(http.MethodGet)
	api.HandleFunc("/config", s.handleGetConfig).Methods(http.MethodGet)
	api.HandleFunc("/config", s.handlePutConfig).Methods(http.MethodPut)
	api.HandleFunc("/connect", s.handleConnect).Methods(http.MethodPost)
	api.HandleFunc("/disconnect", s.handleDisconnect).Methods(http.MethodPost)
	api.HandleFunc("/logs", s.handleLogs).Methods(http.MethodGet)

	// SPA: serve embedded static files for everything else
	r.PathPrefix("/").Handler(staticHandler())
	return r
}
