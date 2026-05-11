package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/neshumov/trusttunnel-webui/internal/api"
	"github.com/neshumov/trusttunnel-webui/internal/logs"
	"github.com/neshumov/trusttunnel-webui/internal/process"
)

func main() {
	defaultClientPath := filepath.Join(os.Getenv("HOME"), "Applications/trusttunnel_client/trusttunnel_client")
	defaultConfigPath := filepath.Join(os.Getenv("HOME"), "Applications/trusttunnel_client/trusttunnel_client.toml")

	clientPath := flag.String("client", defaultClientPath, "path to trusttunnel_client binary")
	configPath := flag.String("config", defaultConfigPath, "path to trusttunnel_client.toml")
	addr := flag.String("addr", "127.0.0.1:7878", "WebUI listen address")
	flag.Parse()

	broker := logs.NewBroker()
	logWriter := logs.NewWriter(broker)
	manager := process.New(*clientPath, *configPath, logWriter)

	srv := api.NewServer(*clientPath, *configPath, manager, broker)

	fmt.Printf("TrustTunnel WebUI → http://%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
