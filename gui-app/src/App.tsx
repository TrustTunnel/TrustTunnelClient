import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { open } from "@tauri-apps/plugin-shell";
import Header from "./components/Header";
import StatusPanel from "./components/StatusPanel";
import LogPanel from "./components/LogPanel";
import SetupWizard from "./components/SetupWizard";
import SettingsPanel from "./components/SettingsPanel";
import RoutingPanel from "./components/RoutingPanel";
import AboutPanel from "./components/AboutPanel";

export type VpnStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "recovering"
  | "error";

export type AppTab = "setup" | "settings" | "routing" | "about";

export interface UpdateInfo {
  available: boolean;
  latestVersion: string;
  currentVersion: string;
  downloadUrl: string;
  releaseNotes: string;
  checking: boolean;
}

export interface VpnConfig {
  configPath: string;
  logLevel: string;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

function App() {
  const [activeTab, setActiveTab] = useState<AppTab>(() => {
    const saved = localStorage.getItem("tt_active_tab");
    const savedConfig = localStorage.getItem("tt_config_path");
    if (saved === "settings" || saved === "routing" || saved === "about") return saved;
    if (savedConfig) return "settings";
    return "setup";
  });
  const [status, setStatus] = useState<VpnStatus>("disconnected");
  const [logs, setLogs] = useState<LogEntry[]>(() => {
    try {
      const saved = sessionStorage.getItem("tt_logs");
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });
  const [config, setConfig] = useState<VpnConfig>(() => {
    const savedPath = localStorage.getItem("tt_config_path") || "";
    const savedLevel = localStorage.getItem("tt_log_level") || "info";
    return { configPath: savedPath, logLevel: savedLevel };
  });
  const [error, setError] = useState<string | null>(null);
  const [connectedSince, setConnectedSince] = useState<Date | null>(() => {
    const saved = localStorage.getItem("tt_connected_since");
    return saved ? new Date(saved) : null;
  });
  // ─── Update check ───
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo>({
    available: false, latestVersion: "", currentVersion: "",
    downloadUrl: "", releaseNotes: "", checking: false,
  });

  const checkForUpdates = useCallback(async (_silent = false) => {
    setUpdateInfo(prev => ({ ...prev, checking: true }));
    try {
      const currentVersion = await getVersion();
      const res = await fetch(
        "https://api.github.com/repos/ialexbond/TrustTunnelClient/releases/latest",
        { headers: { "Accept": "application/vnd.github.v3+json" } }
      );
      if (!res.ok) throw new Error(`GitHub API: ${res.status}`);
      const data = await res.json();
      const latestTag = (data.tag_name || "").replace(/^v/, "");
      const isNewer = compareVersions(latestTag, currentVersion) > 0;
      const asset = data.assets?.find((a: { name: string }) =>
        a.name.endsWith(".exe") || a.name.endsWith(".zip") || a.name.endsWith(".msi")
      );
      setUpdateInfo({
        available: isNewer,
        latestVersion: latestTag,
        currentVersion,
        downloadUrl: asset?.browser_download_url || data.html_url || "",
        releaseNotes: data.body || "",
        checking: false,
      });
    } catch (e) {
      console.warn("Update check failed:", e);
      setUpdateInfo(prev => ({ ...prev, checking: false }));
    }
  }, []);

  // Auto-check on startup (silent)
  useEffect(() => { checkForUpdates(true); }, [checkForUpdates]);

  // Persist tab and config to localStorage
  useEffect(() => { localStorage.setItem("tt_active_tab", activeTab); }, [activeTab]);
  useEffect(() => {
    localStorage.setItem("tt_config_path", config.configPath);
    localStorage.setItem("tt_log_level", config.logLevel);
  }, [config]);
  useEffect(() => { localStorage.setItem("tt_vpn_status", status); }, [status]);

  // Persist logs to sessionStorage (survives WebView2 network-change reloads)
  useEffect(() => {
    try { sessionStorage.setItem("tt_logs", JSON.stringify(logs.slice(-200))); } catch {}
  }, [logs]);

  // Persist connectedSince
  useEffect(() => {
    if (connectedSince) {
      localStorage.setItem("tt_connected_since", connectedSince.toISOString());
    } else {
      localStorage.removeItem("tt_connected_since");
    }
  }, [connectedSince]);

  // On mount: check actual VPN process state from backend
  useEffect(() => {
    invoke<string>("check_vpn_status").then((backendStatus) => {
      if (backendStatus === "connected") {
        setStatus("connected");
        setConnectedSince((prev) => prev ?? new Date());
      } else if (backendStatus === "connecting") {
        setStatus("connecting");
        setConnectedSince(null);
      } else {
        setStatus("disconnected");
        setConnectedSince(null);
      }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    const unlisten = listen<{ message: string; level: string }>(
      "vpn-log",
      (event) => {
        console.log(`[VPN ${event.payload.level}] ${event.payload.message}`);
        setLogs((prev) => [
          ...prev.slice(-500),
          {
            timestamp: new Date().toLocaleTimeString(),
            level: event.payload.level,
            message: event.payload.message,
          },
        ]);
      },
    );

    const unlistenStatus = listen<{ status: VpnStatus; error?: string }>(
      "vpn-status",
      (event) => {
        setStatus(event.payload.status);
        if (event.payload.error) {
          setError(event.payload.error);
        }
        if (event.payload.status === "connected") {
          setConnectedSince(new Date());
        } else if (event.payload.status === "disconnected") {
          setConnectedSince(null);
        }
      },
    );

    return () => {
      unlisten.then((f) => f());
      unlistenStatus.then((f) => f());
    };
  }, []);

  const handleConnect = useCallback(async () => {
    if (!config.configPath) {
      setError("Сначала укажите файл конфигурации или настройте сервер");
      setStatus("error");
      return;
    }
    try {
      setError(null);
      setStatus("connecting");
      await invoke("vpn_connect", {
        configPath: config.configPath,
        logLevel: config.logLevel,
      });
    } catch (e) {
      setError(String(e));
      setStatus("error");
    }
  }, [config]);

  const handleDisconnect = useCallback(async () => {
    try {
      setStatus("disconnecting");
      await invoke("vpn_disconnect");
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const handleSetupComplete = useCallback((configPath: string) => {
    setConfig((prev) => ({ ...prev, configPath }));
    localStorage.setItem("tt_config_path", configPath);
    setActiveTab("settings");
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
    try { sessionStorage.removeItem("tt_logs"); } catch {}
  }, []);

  const handleSwitchToSetup = useCallback(() => {
    setActiveTab("setup");
  }, []);

  const [wizardKey, setWizardKey] = useState(0);

  const handleClearConfig = useCallback(() => {
    setConfig({ configPath: "", logLevel: "info" });
    localStorage.removeItem("tt_config_path");
    // Reset wizard step so it shows welcome screen, not stale "done"
    try {
      const raw = localStorage.getItem("trusttunnel_wizard");
      const obj = raw ? JSON.parse(raw) : {};
      obj.wizardStep = "welcome";
      obj.deploySteps = "{}";
      obj.deployLogs = "[]";
      obj.configPath = "";
      obj.errorMessage = "";
      localStorage.setItem("trusttunnel_wizard", JSON.stringify(obj));
    } catch {}
    // Force wizard remount to pick up reset state
    setWizardKey(k => k + 1);
  }, []);

  return (
    <div className="h-screen flex flex-col bg-surface-950">
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        updateInfo={updateInfo}
        onCheckUpdates={() => checkForUpdates(false)}
        onOpenDownload={() => { if (updateInfo.downloadUrl) open(updateInfo.downloadUrl); }}
      />

      {/* All tabs always mounted; inactive hidden via display:none to preserve state */}
      <div className="flex-1 flex flex-col overflow-hidden" style={{ display: activeTab === "setup" ? "flex" : "none" }}>
        <SetupWizard key={wizardKey} onSetupComplete={handleSetupComplete} />
      </div>

      <div className="flex-1 flex flex-col gap-2 p-3 overflow-hidden" style={{ display: activeTab === "settings" ? "flex" : "none" }}>
        <StatusPanel
          status={status}
          error={error}
          connectedSince={connectedSince}
          onConnect={handleConnect}
          onDisconnect={handleDisconnect}
        />
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-2 min-h-0">
          <SettingsPanel
            configPath={config.configPath}
            onConfigChange={setConfig}
            status={status}
            onReconnect={async () => {
              if (status === "connected" || status === "connecting") {
                await handleDisconnect();
                // Small delay before reconnecting
                setTimeout(() => handleConnect(), 500);
              }
            }}
            onSwitchToSetup={handleSwitchToSetup}
            onClearConfig={handleClearConfig}
          />
          <LogPanel logs={logs} onClear={clearLogs} />
        </div>
      </div>

      <div className="flex-1 flex flex-col p-3 overflow-hidden" style={{ display: activeTab === "routing" ? "flex" : "none" }}>
        <RoutingPanel />
      </div>

      <div className="flex-1 flex flex-col overflow-hidden" style={{ display: activeTab === "about" ? "flex" : "none" }}>
        <AboutPanel
          updateInfo={updateInfo}
          onCheckUpdates={() => checkForUpdates(false)}
          onOpenDownload={() => { if (updateInfo.downloadUrl) open(updateInfo.downloadUrl); }}
        />
      </div>
    </div>
  );
}

export default App;
