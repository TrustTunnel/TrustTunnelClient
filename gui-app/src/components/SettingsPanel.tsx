import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Settings, FolderOpen, Save, Eye, EyeOff, Trash2, AlertTriangle, Loader2, Download } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import type { VpnConfig, VpnStatus } from "../App";

interface SettingsPanelProps {
  configPath: string;
  onConfigChange: (config: VpnConfig) => void;
  status: VpnStatus;
  onReconnect: () => Promise<void>;
  onSwitchToSetup: () => void;
  onClearConfig: () => void;
}

interface ClientConfig {
  loglevel: string;
  vpn_mode: string;
  killswitch_enabled: boolean;
  post_quantum_group_enabled: boolean;
  endpoint: {
    hostname: string;
    addresses: string[];
    upstream_protocol: string;
    anti_dpi: boolean;
    skip_verification: boolean;
    custom_sni: string;
    has_ipv6: boolean;
    username: string;
    password: string;
    [key: string]: unknown;
  };
  listener: {
    tun: {
      mtu_size: number;
      change_system_dns: boolean;
      included_routes: string[];
      excluded_routes: string[];
    };
  };
  [key: string]: unknown;
}

const LOG_LEVELS = ["error", "warn", "info", "debug", "trace"];

function Toggle({
  value,
  onChange,
  label,
  description,
}: {
  value: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <div
      className="flex items-center justify-between py-1.5 cursor-pointer group"
      onClick={() => onChange(!value)}
    >
      <div className="min-w-0">
        <span className="text-xs text-gray-200 group-hover:text-white transition-colors">
          {label}
        </span>
        {description && (
          <p className="text-[10px] text-gray-500 mt-0.5">{description}</p>
        )}
      </div>
      <div
        className={`relative w-9 h-5 rounded-full shrink-0 ml-3 transition-colors ${
          value ? "bg-indigo-500" : "bg-white/10"
        }`}
      >
        <div
          className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${
            value ? "translate-x-4" : "translate-x-0.5"
          }`}
        />
      </div>
    </div>
  );
}

function DangerZone({ onSwitchToSetup, onClearConfig }: { onSwitchToSetup: () => void; onClearConfig: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [phase, setPhase] = useState<"idle" | "confirming" | "checking" | "uninstalling" | "not_found">("idle");
  const [host, setHost] = useState(() => {
    try { const raw = localStorage.getItem("trusttunnel_wizard"); return raw ? JSON.parse(raw).host || "" : ""; } catch { return ""; }
  });
  const [port, setPort] = useState(() => {
    try { const raw = localStorage.getItem("trusttunnel_wizard"); return raw ? JSON.parse(raw).port || "22" : "22"; } catch { return "22"; }
  });
  const [user, setUser] = useState(() => {
    try { const raw = localStorage.getItem("trusttunnel_wizard"); return raw ? JSON.parse(raw).sshUser || "root" : "root"; } catch { return "root"; }
  });
  const [password, setPassword] = useState(() => {
    try { const raw = localStorage.getItem("trusttunnel_wizard"); return raw ? JSON.parse(raw).sshPassword || "" : ""; } catch { return ""; }
  });
  const [showPw, setShowPw] = useState(false);
  const [result, setResult] = useState<"" | "ok" | "error">("");
  const [resultMsg, setResultMsg] = useState("");

  useEffect(() => {
    const unlisten = listen<{ step: string; status: string; message: string }>(
      "deploy-step",
      (event) => {
        if (event.payload.step === "uninstall") {
          if (event.payload.status === "ok") {
            setPhase("idle");
            // Auto-disconnect VPN client since server is gone
            invoke("vpn_disconnect").catch(() => {});
            // Clear config and switch to setup tab
            onClearConfig();
            onSwitchToSetup();
          } else if (event.payload.status === "error") {
            setPhase("idle");
            setResult("error");
            setResultMsg(event.payload.message);
          }
        }
      }
    );
    return () => { unlisten.then((f) => f()); };
  }, [onClearConfig, onSwitchToSetup]);

  const handleConfirm = async () => {
    if (!host || !password) return;
    setPhase("checking");
    setResult("");
    setResultMsg("");
    try {
      const info = await invoke<{ installed: boolean; version: string; service_active: boolean }>(
        "check_server_installation",
        { host, port: parseInt(port), user, password }
      );
      if (!info.installed) {
        setPhase("not_found");
      } else {
        // TT found — proceed with uninstall
        setPhase("uninstalling");
        await invoke("uninstall_server", { host, port: parseInt(port), user, password });
      }
    } catch (e) {
      setPhase("idle");
      setResult("error");
      setResultMsg(String(e));
    }
  };

  return (
    <div className="pt-3 border-t border-red-500/10">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1.5 text-[10px] text-red-400/60 hover:text-red-400 transition-colors"
      >
        <AlertTriangle className="w-3 h-3" />
        Опасная зона
      </button>
      {expanded && (
        <div className="mt-2 space-y-2 p-2.5 rounded-lg border border-red-500/20 bg-red-500/5">
          <p className="text-[10px] text-red-300/80 leading-relaxed">
            Полностью удалить TrustTunnel с сервера: остановка сервиса, удаление файлов и конфигурации.
          </p>
          <div className="grid grid-cols-3 gap-1.5">
            <input type="text" value={host} onChange={(e) => setHost(e.target.value)}
              placeholder="IP сервера" className="col-span-2 bg-white/5 border border-white/10 rounded px-2 py-1 text-[10px] text-gray-200 placeholder-gray-600" />
            <input type="text" value={port} onChange={(e) => setPort(e.target.value)}
              placeholder="22" className="bg-white/5 border border-white/10 rounded px-2 py-1 text-[10px] text-gray-200 placeholder-gray-600" />
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            <input type="text" value={user} onChange={(e) => setUser(e.target.value)}
              placeholder="root" className="bg-white/5 border border-white/10 rounded px-2 py-1 text-[10px] text-gray-200 placeholder-gray-600" />
            <div className="relative">
              <input type={showPw ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)}
                placeholder="Пароль SSH" className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 pr-7 text-[10px] text-gray-200 placeholder-gray-600" />
              <button type="button" onClick={() => setShowPw(!showPw)}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                {showPw ? <EyeOff className="w-2.5 h-2.5" /> : <Eye className="w-2.5 h-2.5" />}
              </button>
            </div>
          </div>

          {result === "error" && (
            <p className="text-[10px] text-red-400">{resultMsg}</p>
          )}

          {/* VPN not found on server — offer to install */}
          {phase === "not_found" && (
            <div className="p-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 space-y-2">
              <p className="text-[11px] text-amber-300 font-medium text-center">
                VPN не найден на сервере
              </p>
              <p className="text-[10px] text-amber-300/60 text-center">
                TrustTunnel не установлен на этом сервере. Хотите установить?
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => { setPhase("idle"); setExpanded(false); }}
                  className="flex-1 px-3 py-1.5 rounded-lg text-[11px] text-gray-400
                             border border-white/10 hover:bg-white/5 transition-all"
                >
                  Нет
                </button>
                <button
                  onClick={() => {
                    setPhase("idle");
                    // Save SSH credentials to wizard storage so endpoint step has them
                    try {
                      const raw = localStorage.getItem("trusttunnel_wizard");
                      const obj = raw ? JSON.parse(raw) : {};
                      obj.host = host;
                      obj.port = port;
                      obj.sshUser = user;
                      obj.sshPassword = password;
                      obj.wizardStep = "endpoint";
                      localStorage.setItem("trusttunnel_wizard", JSON.stringify(obj));
                    } catch {}
                    onClearConfig();
                    onSwitchToSetup();
                  }}
                  className="flex-1 flex items-center justify-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium
                             bg-indigo-500/30 border border-indigo-500/50 text-indigo-300 hover:bg-indigo-500/40 transition-all"
                >
                  <Download className="w-3 h-3" />
                  Установить
                </button>
              </div>
            </div>
          )}

          {/* Confirmation dialog */}
          {phase === "confirming" && (
            <div className="p-2.5 rounded-lg border border-red-500/30 bg-red-500/10 space-y-2">
              <p className="text-[11px] text-red-300 font-medium text-center">
                Вы уверены? Это действие необратимо.
              </p>
              <p className="text-[10px] text-red-300/60 text-center">
                Сервис будет остановлен, все файлы TrustTunnel будут удалены с сервера.
                {" "}Текущее VPN-подключение будет разорвано.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPhase("idle")}
                  className="flex-1 px-3 py-1.5 rounded-lg text-[11px] text-gray-400
                             border border-white/10 hover:bg-white/5 transition-all"
                >
                  Отмена
                </button>
                <button
                  onClick={handleConfirm}
                  className="flex-1 px-3 py-1.5 rounded-lg text-[11px] font-medium
                             bg-red-500/30 border border-red-500/50 text-red-300 hover:bg-red-500/40 transition-all"
                >
                  Да, удалить
                </button>
              </div>
            </div>
          )}

          {/* Checking / Uninstalling spinner */}
          {(phase === "checking" || phase === "uninstalling") && (
            <div className="flex items-center justify-center gap-2 py-2">
              <Loader2 className="w-4 h-4 text-red-400 animate-spin" />
              <span className="text-[11px] text-red-300">
                {phase === "checking" ? "Проверка сервера..." : "Удаление..."}
              </span>
            </div>
          )}

          {/* Main button — only shown in idle state */}
          {phase === "idle" && (
            <button
              onClick={() => setPhase("confirming")}
              disabled={!host || !password}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium
                         bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500/30
                         disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Удалить VPN с сервера
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function SettingsPanel({
  configPath,
  onConfigChange,
  status,
  onReconnect,
  onSwitchToSetup,
  onClearConfig,
}: SettingsPanelProps) {
  const [config, setConfig] = useState<ClientConfig | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [localPath, setLocalPath] = useState(configPath);
  const [showPass, setShowPass] = useState(false);

  useEffect(() => {
    setLocalPath(configPath);
    if (!configPath) {
      setConfig(null);
      setError("");
      setDirty(false);
    }
  }, [configPath]);

  const loadConfig = useCallback(async () => {
    if (!localPath) return;
    try {
      setError("");
      const data = await invoke<ClientConfig>("read_client_config", {
        configPath: localPath,
      });
      setConfig(data);
      setDirty(false);
    } catch (e) {
      setError(String(e));
    }
  }, [localPath]);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const updateField = useCallback(
    (path: string, value: unknown) => {
      if (!config) return;
      const clone = JSON.parse(JSON.stringify(config));
      const parts = path.split(".");
      let obj = clone;
      for (let i = 0; i < parts.length - 1; i++) {
        obj = obj[parts[i]];
      }
      obj[parts[parts.length - 1]] = value;
      setConfig(clone);
      setDirty(true);
    },
    [config]
  );

  const handleSave = useCallback(async () => {
    if (!config || !localPath) return;
    setSaving(true);
    setError("");
    try {
      await invoke("save_client_config", {
        configPath: localPath,
        config,
      });
      setDirty(false);
      onConfigChange({ configPath: localPath, logLevel: config.loglevel });
      // Reconnect if VPN is active
      if (status === "connected" || status === "connecting") {
        await onReconnect();
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }, [config, localPath, onConfigChange, status, onReconnect]);

  return (
    <div className="glass-card lg:col-span-1 overflow-hidden">
    <div className="p-3 flex flex-col gap-2 overflow-y-auto h-full">
      <div className="flex items-center gap-2">
        <Settings className="w-3.5 h-3.5 text-indigo-400" />
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          Настройки
        </h2>
      </div>

      {/* Config file path */}
      <div>
        <label className="block text-[10px] text-gray-500 mb-1">
          Файл конфигурации
        </label>
        <div className="flex gap-1.5">
          <input
            type="text"
            value={localPath}
            onChange={(e) => setLocalPath(e.target.value)}
            onBlur={() => {
              onConfigChange({ configPath: localPath, logLevel: config?.loglevel || "info" });
            }}
            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                       text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500/50
                       focus:ring-1 focus:ring-indigo-500/25 transition-colors"
            placeholder="trusttunnel_client.toml"
          />
          <button
            onClick={async () => {
              // Open dialog in the directory of the current config file
              let defaultPath: string | undefined;
              if (localPath) {
                const sep = localPath.includes("/") ? "/" : "\\";
                const lastSep = localPath.lastIndexOf(sep);
                if (lastSep > 0) defaultPath = localPath.substring(0, lastSep);
              }
              const selected = await open({
                multiple: false,
                defaultPath,
                filters: [{ name: "TOML Config", extensions: ["toml"] }],
              });
              if (selected) {
                setLocalPath(selected as string);
                onConfigChange({ configPath: selected as string, logLevel: config?.loglevel || "info" });
              }
            }}
            className="p-1.5 bg-white/5 border border-white/10 rounded-lg
                       hover:bg-white/10 transition-colors text-gray-400 hover:text-gray-200"
            title="Выбрать файл"
          >
            <FolderOpen className="w-3 h-3" />
          </button>
        </div>
      </div>

      {error && (
        <div className="text-[10px] text-red-400 bg-red-400/10 rounded px-2 py-1">
          {error}
        </div>
      )}

      {config && (
        <div className="space-y-2 flex-1">
          {/* Connection */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Подключение</span>
            <div>
              <label className="block text-[10px] text-gray-500 mb-0.5">Хост</label>
              <input
                type="text"
                value={config.endpoint?.hostname || ""}
                onChange={(e) => updateField("endpoint.hostname", e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                           text-gray-200 focus:outline-none focus:border-indigo-500/50
                           focus:ring-1 focus:ring-indigo-500/25 transition-colors"
              />
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <label className="block text-[10px] text-gray-500 mb-0.5">Логин</label>
                <input
                  type="text"
                  value={config.endpoint?.username || ""}
                  onChange={(e) => updateField("endpoint.username", e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                             text-gray-200 focus:outline-none focus:border-indigo-500/50
                             focus:ring-1 focus:ring-indigo-500/25 transition-colors"
                />
              </div>
              <div>
                <label className="block text-[10px] text-gray-500 mb-0.5">Пароль</label>
                <div className="relative">
                  <input
                    type={showPass ? "text" : "password"}
                    value={config.endpoint?.password || ""}
                    onChange={(e) => updateField("endpoint.password", e.target.value)}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 pr-7 text-[11px]
                               text-gray-200 focus:outline-none focus:border-indigo-500/50
                               focus:ring-1 focus:ring-indigo-500/25 transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass(!showPass)}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  >
                    {showPass ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* VPN Mode */}
          <div className="border-t border-white/5 pt-2">
            <label className="block text-[10px] text-gray-500 mb-1">Режим VPN</label>
            <div className="grid grid-cols-2 gap-1">
              <button
                onClick={() => updateField("vpn_mode", "general")}
                className={`px-2 py-1.5 rounded-lg text-[11px] font-medium transition-all border ${
                  config.vpn_mode === "general"
                    ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300"
                    : "bg-white/5 border-white/10 text-gray-400 hover:text-gray-200"
                }`}
              >
                Всё через VPN
              </button>
              <button
                onClick={() => updateField("vpn_mode", "selective")}
                className={`px-2 py-1.5 rounded-lg text-[11px] font-medium transition-all border ${
                  config.vpn_mode === "selective"
                    ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300"
                    : "bg-white/5 border-white/10 text-gray-400 hover:text-gray-200"
                }`}
              >
                Только избранное
              </button>
            </div>
            <p className="text-[9px] text-gray-600 mt-0.5">
              {config.vpn_mode === "general"
                ? "Весь трафик через VPN, кроме исключений"
                : "Весь трафик напрямую, кроме указанных маршрутов"}
            </p>
          </div>

          {/* Toggles */}
          <div className="border-t border-white/5 pt-2 space-y-0.5">
            <Toggle
              label="Kill Switch"
              description="Блокировать интернет при обрыве VPN"
              value={config.killswitch_enabled}
              onChange={(v) => updateField("killswitch_enabled", v)}
            />
            <Toggle
              label="Anti-DPI"
              description="Обход блокировок DPI"
              value={config.endpoint?.anti_dpi || false}
              onChange={(v) => updateField("endpoint.anti_dpi", v)}
            />
            <Toggle
              label="Post-Quantum"
              description="Постквантовая криптография"
              value={config.post_quantum_group_enabled}
              onChange={(v) => updateField("post_quantum_group_enabled", v)}
            />
            <Toggle
              label="Системный DNS"
              description="Менять DNS системы при подключении"
              value={config.listener?.tun?.change_system_dns || false}
              onChange={(v) => updateField("listener.tun.change_system_dns", v)}
            />
            <Toggle
              label="IPv6"
              description="Разрешить IPv6 трафик через VPN"
              value={config.endpoint?.has_ipv6 || false}
              onChange={(v) => updateField("endpoint.has_ipv6", v)}
            />
          </div>

          {/* Advanced */}
          <div className="border-t border-white/5 pt-2 space-y-1.5">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Дополнительно</span>
            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <label className="block text-[10px] text-gray-500 mb-0.5">MTU</label>
                <input
                  type="number"
                  value={config.listener?.tun?.mtu_size || 1280}
                  onChange={(e) => updateField("listener.tun.mtu_size", Number(e.target.value))}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                             text-gray-200 focus:outline-none focus:border-indigo-500/50
                             focus:ring-1 focus:ring-indigo-500/25 transition-colors"
                />
              </div>
              <div>
                <label className="block text-[10px] text-gray-500 mb-0.5">Протокол</label>
                <select
                  value={config.endpoint?.upstream_protocol || "http2"}
                  onChange={(e) => updateField("endpoint.upstream_protocol", e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                             text-gray-200 focus:outline-none focus:border-indigo-500/50
                             focus:ring-1 focus:ring-indigo-500/25 transition-colors appearance-none"
                >
                  <option value="http2" className="bg-surface-900">HTTP/2</option>
                  <option value="http3" className="bg-surface-900">HTTP/3</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-[10px] text-gray-500 mb-0.5">Custom SNI</label>
              <input
                type="text"
                value={config.endpoint?.custom_sni || ""}
                onChange={(e) => updateField("endpoint.custom_sni", e.target.value)}
                placeholder="Оставьте пустым для hostname"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                           text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500/50
                           focus:ring-1 focus:ring-indigo-500/25 transition-colors"
              />
            </div>
            <div>
              <label className="block text-[10px] text-gray-500 mb-0.5">Уровень логирования</label>
              <select
                value={config.loglevel}
                onChange={(e) => updateField("loglevel", e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-[11px]
                           text-gray-200 focus:outline-none focus:border-indigo-500/50
                           focus:ring-1 focus:ring-indigo-500/25 transition-colors appearance-none"
              >
                {LOG_LEVELS.map((level) => (
                  <option key={level} value={level} className="bg-surface-900">
                    {level.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Save button */}
          <div className="pt-2 border-t border-white/5">
            <button
              onClick={handleSave}
              disabled={!dirty || saving}
              className={`w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                dirty
                  ? "bg-indigo-500 hover:bg-indigo-400 text-white"
                  : "bg-white/5 text-gray-500 cursor-not-allowed"
              }`}
            >
              <Save className="w-3.5 h-3.5" />
              {saving
                ? "Сохранение..."
                : dirty
                ? "Сохранить и переподключить"
                : "Настройки сохранены"}
            </button>
          </div>

          {/* Danger Zone */}
          <DangerZone onSwitchToSetup={onSwitchToSetup} onClearConfig={onClearConfig} />
        </div>
      )}

      {!config && !error && (
        <div className="flex-1 flex items-center justify-center text-gray-600 text-xs">
          Укажите путь к конфигу...
        </div>
      )}
    </div>
    </div>
  );
}

export default SettingsPanel;
