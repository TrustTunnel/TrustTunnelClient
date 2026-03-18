import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { GitBranch, Globe, Plus, Trash2, Loader2, RefreshCw, Upload } from "lucide-react";
import type { VpnStatus } from "../App";

interface RoutingPanelProps {
  configPath: string;
  status: VpnStatus;
  onReconnect: () => Promise<void>;
}

function RoutingPanel({ configPath, status, onReconnect }: RoutingPanelProps) {
  const [domains, setDomains] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [needsReconnect, setNeedsReconnect] = useState(false);
  const [input, setInput] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const isActive = status === "connected" || status === "connecting" || status === "recovering";

  // JSON backup domains (survives config deletion)
  const [jsonBackupDomains, setJsonBackupDomains] = useState<string[]>([]);
  const [showImportBanner, setShowImportBanner] = useState(false);

  useEffect(() => {
    if (!configPath) {
      // No config — check if JSON backup has domains
      invoke<string[]>("load_exclusion_json")
        .then((jsonDomains) => {
          if (jsonDomains.length > 0) {
            setJsonBackupDomains(jsonDomains);
            setShowImportBanner(true);
          }
        })
        .catch(console.warn)
        .finally(() => setLoading(false));
      return;
    }
    invoke<string[]>("load_exclusion_list", { configPath })
      .then((tomlDomains) => {
        setDomains(tomlDomains);
        // Check if JSON has domains that TOML doesn't
        invoke<string[]>("load_exclusion_json")
          .then((jsonDomains) => {
            const hasNew = jsonDomains.some((d) => !tomlDomains.includes(d));
            if (jsonDomains.length > 0 && hasNew) {
              setJsonBackupDomains(jsonDomains);
              setShowImportBanner(true);
            }
          })
          .catch(console.warn);
      })
      .catch(console.warn)
      .finally(() => setLoading(false));
  }, [configPath]);

  const save = useCallback(async (newDomains: string[]) => {
    setDomains(newDomains);
    setSaving(true);
    try {
      // Always save to JSON backup
      await invoke("save_exclusion_json", { domains: newDomains });
      // Save to TOML if config exists
      if (configPath) {
        await invoke("save_exclusion_list", { configPath, domains: newDomains });
      }
      setNeedsReconnect(true);
    } catch (e) {
      console.error("Failed to save:", e);
    } finally {
      setSaving(false);
    }
  }, [configPath]);

  const handleImportFromJson = useCallback(async () => {
    if (!configPath) return;
    // Merge: add only domains not already present
    const merged = [...domains];
    for (const d of jsonBackupDomains) {
      if (!merged.includes(d)) merged.push(d);
    }
    await save(merged);
    setShowImportBanner(false);
  }, [configPath, jsonBackupDomains, domains, save]);

  const handleClearAll = useCallback(async () => {
    await save([]);
  }, [save]);

  const handleReconnect = useCallback(async () => {
    setReconnecting(true);
    setNeedsReconnect(false);
    try {
      await onReconnect();
    } finally {
      setReconnecting(false);
    }
  }, [onReconnect]);

  const addDomain = () => {
    const val = input.trim().toLowerCase();
    if (!val || domains.includes(val)) return;
    save([...domains, val]);
    setInput("");
    inputRef.current?.focus();
  };

  const removeDomain = (idx: number) =>
    save(domains.filter((_, i) => i !== idx));

  if (!configPath) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-2 text-gray-600">
        <Globe className="w-8 h-8" />
        <p className="text-xs">Конфигурация не выбрана</p>
        <p className="text-[10px]">Настройте подключение на вкладке Настройки</p>
        {showImportBanner && jsonBackupDomains.length > 0 && (
          <div className="mt-3 px-3 py-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-center max-w-xs">
            <p className="text-[11px] text-indigo-300 mb-1">
              Найдено {jsonBackupDomains.length} сохранённых доменов
            </p>
            <p className="text-[10px] text-gray-500">
              Они будут автоматически подгружены в конфиг после настройки подключения.
            </p>
          </div>
        )}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-indigo-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col gap-3 overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="p-2 rounded-lg bg-indigo-500/20">
          <GitBranch className="w-5 h-5 text-indigo-400" />
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-sm font-semibold text-gray-200">Исключения VPN</h2>
          <p className="text-[10px] text-gray-500">
            {domains.length} записей · {saving ? "сохранение..." : "авто-сохранение"}
          </p>
        </div>
        {domains.length > 0 && (
          <button
            onClick={handleClearAll}
            disabled={saving}
            className="px-2.5 py-1 rounded-md bg-red-500/10 text-red-400 text-[11px] hover:bg-red-500/20 transition-colors disabled:opacity-50"
            title="Удалить все"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Reconnect banner */}
      {needsReconnect && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30 shrink-0">
          <RefreshCw className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <p className="flex-1 text-[11px] text-amber-300">
            {isActive ? "Список изменён — нужен перезапуск" : "Список изменён — применится при подключении"}
          </p>
          {isActive && (
            <button
              onClick={handleReconnect}
              disabled={reconnecting}
              className="px-2.5 py-1 rounded-md bg-amber-500/20 text-amber-300 text-[11px] font-medium hover:bg-amber-500/30 transition-colors disabled:opacity-50"
            >
              {reconnecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Переподключить"}
            </button>
          )}
        </div>
      )}

      {/* Import from JSON banner */}
      {showImportBanner && jsonBackupDomains.length > 0 && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 shrink-0">
          <Upload className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
          <p className="flex-1 text-[11px] text-indigo-300">
            Найдено {jsonBackupDomains.length} ранее сохранённых доменов
          </p>
          <button
            onClick={handleImportFromJson}
            disabled={saving}
            className="px-2.5 py-1 rounded-md bg-indigo-500/20 text-indigo-300 text-[11px] font-medium hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
          >
            Подгрузить
          </button>
          <button
            onClick={() => setShowImportBanner(false)}
            className="px-2 py-1 rounded-md text-gray-500 text-[11px] hover:text-gray-300 transition-colors"
          >
            ✕
          </button>
        </div>
      )}

      {/* Info */}
      {!needsReconnect && !showImportBanner && (
        <div className="px-3 py-2 rounded-lg bg-surface-900/30 border border-white/5 shrink-0">
          <p className="text-[11px] text-gray-400">
            Домены обрабатываются согласно <span className="text-amber-300">vpn_mode</span> в конфиге.
            Применяется при подключении.
          </p>
        </div>
      )}

      {/* Input */}
      <div className="flex gap-2 shrink-0">
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") addDomain(); }}
          placeholder="example.com, *.google.com, 192.168.1.0/24..."
          className="flex-1 px-3 py-2 rounded-lg bg-surface-900/50 border border-white/10 text-xs text-gray-200 placeholder-gray-600 focus:border-indigo-500/50 focus:outline-none font-mono"
        />
        <button
          onClick={addDomain}
          disabled={!input.trim()}
          className="px-3 py-2 rounded-lg bg-indigo-500/20 text-indigo-300 hover:bg-indigo-500/30 transition-colors disabled:opacity-40 disabled:cursor-default"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>

      {/* Domain list */}
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {domains.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 text-gray-600">
            <Globe className="w-8 h-8" />
            <p className="text-xs">Список пуст</p>
            <p className="text-[10px]">Добавьте домены или IP-адреса выше</p>
          </div>
        ) : (
          domains.map((domain, idx) => (
            <div
              key={`${domain}-${idx}`}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-900/30 border border-white/5 group"
            >
              <Globe className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span className="flex-1 text-xs text-gray-300 truncate font-mono">{domain}</span>
              <button
                onClick={() => removeDomain(idx)}
                className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-red-500/10 transition-all"
                title="Удалить"
              >
                <Trash2 className="w-3.5 h-3.5 text-gray-500 hover:text-red-400" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default RoutingPanel;
