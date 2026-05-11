BINARY   := trusttunnel-webui
WEB_DIR  := web
GO_BIN   := $(shell which go)
NODE     := /tmp/node_unlocked

# Prepare a node binary with library-validation disabled (macOS Team ID fix).
# Only needs to run once per machine.
$(NODE):
	cp /opt/homebrew/bin/node $(NODE)
	@cat > /tmp/node_ent.plist <<'EOF'\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n  <key>com.apple.security.cs.disable-library-validation</key><true/>\n</dict></plist>\nEOF
	codesign --entitlements /tmp/node_ent.plist --sign - --force $(NODE)

.PHONY: setup
setup: ## Install npm dependencies
	cd $(WEB_DIR) && /opt/homebrew/bin/npm install

.PHONY: node-unlock
node-unlock: ## Create ad-hoc signed node with disabled library validation (fixes macOS 25 Team ID issue)
	cp /opt/homebrew/bin/node $(NODE)
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>' > /tmp/node_ent.plist
	codesign --entitlements /tmp/node_ent.plist --sign - --force $(NODE)
	@echo "node_unlocked ready at $(NODE)"

.PHONY: web
web: ## Build the React frontend (requires node-unlock first)
	cd $(WEB_DIR) && $(NODE) build.mjs

.PHONY: build
build: web ## Build Go binary with embedded frontend
	$(GO_BIN) build -o $(BINARY) ./cmd/webui/

.PHONY: run
run: build ## Build and run the WebUI daemon
	./$(BINARY)

.PHONY: dev-web
dev-web: ## Start Vite dev server (use with `make run` in another terminal)
	cd $(WEB_DIR) && /opt/homebrew/bin/npm run dev

.PHONY: clean
clean: ## Remove built artifacts
	rm -f $(BINARY)
	rm -rf internal/api/dist/assets

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
