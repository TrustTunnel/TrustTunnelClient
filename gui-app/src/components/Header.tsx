import { Shield, Wand2, Settings, GitBranch, Download, RefreshCw, Loader2 } from "lucide-react";
import type { AppTab, UpdateInfo } from "../App";

interface HeaderProps {
  activeTab: AppTab;
  onTabChange: (tab: AppTab) => void;
  updateInfo?: UpdateInfo;
  onCheckUpdates?: () => void;
  onOpenDownload?: () => void;
}

const TABS: { id: AppTab; label: string; icon: React.ReactNode }[] = [
  { id: "setup", label: "Установка VPN", icon: <Wand2 className="w-3.5 h-3.5" /> },
  { id: "settings", label: "Настройки", icon: <Settings className="w-3.5 h-3.5" /> },
  { id: "routing", label: "Маршрутизация", icon: <GitBranch className="w-3.5 h-3.5" /> },
];

function Header({ activeTab, onTabChange, updateInfo, onCheckUpdates, onOpenDownload }: HeaderProps) {
  return (
    <header
      className="flex items-center gap-3 px-5 py-3 border-b border-white/10 bg-surface-900/50 backdrop-blur-sm"
      data-tauri-drag-region
    >
      <div className="p-2 rounded-lg bg-indigo-500/20">
        <Shield className="w-5 h-5 text-indigo-400" />
      </div>
      <div className="mr-4">
        <h1 className="text-sm font-bold tracking-wide">TrustTunnel</h1>
        <p className="text-[10px] text-gray-500 uppercase tracking-widest">
          VPN Client
        </p>
      </div>

      <div className="flex items-center gap-2 ml-auto">
        {updateInfo?.available && (
          <button
            onClick={onOpenDownload}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 transition-colors animate-pulse"
            title={`Доступна версия ${updateInfo.latestVersion}`}
          >
            <Download className="w-3.5 h-3.5" />
            v{updateInfo.latestVersion}
          </button>
        )}
        <button
          onClick={onCheckUpdates}
          disabled={updateInfo?.checking}
          className="p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-colors disabled:opacity-50"
          title={updateInfo?.checking ? "Проверка..." : `Проверить обновления (v${updateInfo?.currentVersion || "?"})`}
        >
          {updateInfo?.checking
            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
            : <RefreshCw className="w-3.5 h-3.5" />
          }
        </button>
      </div>

      <nav className="flex gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200
              ${
                activeTab === tab.id
                  ? "bg-white/10 text-white"
                  : "text-gray-500 hover:text-gray-300 hover:bg-white/5"
              }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </nav>

      {updateInfo?.available && (
        <div className="hidden lg:flex items-center text-[10px] text-emerald-400/70 ml-2">
          Текущая: v{updateInfo.currentVersion}
        </div>
      )}
    </header>
  );
}

export default Header;
