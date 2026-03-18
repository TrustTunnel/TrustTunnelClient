import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Shield,
  Server,
  Settings,
  Loader2,
  CheckCircle2,
  XCircle,
  Eye,
  EyeOff,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Rocket,
  Globe,
  Lock,
  User,
  Copy,
  ClipboardCheck,
  FolderOpen,
  AlertTriangle,
  Mail,
  Info,
  Trash2,
  PackageCheck,
  SkipForward,
  Download,
} from "lucide-react";

interface DeployStep {
  step: string;
  status: string;
  message: string;
}

interface DeployLog {
  message: string;
  level: string;
}

type WizardStep = "welcome" | "server" | "checking" | "found" | "uninstalling" | "endpoint" | "deploying" | "fetching" | "done" | "error";

interface SetupWizardProps {
  onSetupComplete: (configPath: string) => void;
}

const STEPS_ORDER = [
  "connect", "auth", "check", "update", "install", "configure", "service", "export", "save", "done",
];
const STEP_LABELS: Record<string, string> = {
  connect: "Подключение к серверу",
  auth: "Авторизация",
  check: "Проверка окружения",
  update: "Обновление системы",
  install: "Установка TrustTunnel",
  configure: "Настройка Endpoint",
  service: "Запуск сервиса",
  export: "Экспорт конфига",
  save: "Сохранение",
  done: "Готово",
};

// localStorage helpers
const STORAGE_KEY = "trusttunnel_wizard";

function loadSaved<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const obj = JSON.parse(raw);
    return obj[key] !== undefined ? obj[key] : fallback;
  } catch {
    return fallback;
  }
}

function saveField(key: string, value: unknown) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const obj = raw ? JSON.parse(raw) : {};
    obj[key] = value;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
  } catch { /* ignore */ }
}

function SetupWizard({ onSetupComplete }: SetupWizardProps) {
  // Wizard navigation — persisted so tab switches don't reset
  const [wizardStep, setWizardStepRaw] = useState<WizardStep>(() => {
    const saved = loadSaved("wizardStep", "welcome") as WizardStep;
    // "done"/"deploying"/"fetching" only make sense if a config file was actually saved
    const hasConfig = !!localStorage.getItem("tt_config_path");
    if ((saved === "done" || saved === "deploying" || saved === "fetching") && !hasConfig) return "welcome";
    // Restore only stable steps; transient steps fall back to safe defaults
    const restorable: WizardStep[] = ["welcome", "server", "found", "endpoint", "done", "error"];
    if (restorable.includes(saved)) return saved;
    // "deploying"/"fetching" are dead after restart — go back to endpoint so user can retry
    if (saved === "deploying" || saved === "fetching") return "endpoint";
    if (saved === "checking" || saved === "uninstalling") return "server";
    return "welcome";
  });
  const setWizardStep = useCallback((step: WizardStep) => {
    setWizardStepRaw(step);
    saveField("wizardStep", step);
  }, []);

  // SSH credentials (persisted)
  const [host, setHost] = useState(() => loadSaved("host", ""));
  const [port, setPort] = useState(() => loadSaved("port", "22"));
  const [sshUser, setSshUser] = useState(() => loadSaved("sshUser", "root"));
  const [sshPassword, setSshPassword] = useState(() => loadSaved("sshPassword", ""));
  const [showSshPassword, setShowSshPassword] = useState(false);

  // Endpoint settings (persisted)
  const [listenAddress, setListenAddress] = useState(() => loadSaved("listenAddress", "0.0.0.0:443"));
  const [vpnUsername, setVpnUsername] = useState(() => loadSaved("vpnUsername", ""));
  const [vpnPassword, setVpnPassword] = useState(() => loadSaved("vpnPassword", ""));
  const [showVpnPassword, setShowVpnPassword] = useState(false);
  const [certType, setCertType] = useState<"selfsigned" | "letsencrypt">(() => loadSaved("certType", "letsencrypt"));
  const [domain, setDomain] = useState(() => loadSaved("domain", ""));
  const [email, setEmail] = useState(() => loadSaved("email", ""));
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [fetchClientName, setFetchClientName] = useState(() => loadSaved("fetchClientName", ""));

  // Fetch retry count — tracks consecutive fetch failures for reinstall prompt
  const [fetchRetryCount, setFetchRetryCount] = useState(0);

  // Server check state
  const [serverInfo, setServerInfo] = useState<{
    installed: boolean;
    version: string;
    serviceActive: boolean;
  } | null>(null);
  const [checkError, setCheckError] = useState("");
  const [confirmUninstall, setConfirmUninstall] = useState(false);

  // Deploy state — persisted
  const [deploySteps, setDeploySteps] = useState<Record<string, DeployStep>>(() => {
    try { return JSON.parse(loadSaved("deploySteps", "{}") as string); } catch { return {}; }
  });
  const [deployLogs, setDeployLogs] = useState<DeployLog[]>(() => {
    try { return JSON.parse(loadSaved("deployLogs", "[]") as string) as DeployLog[]; } catch { return []; }
  });
  const [showLogs, setShowLogs] = useState(false);
  const [errorMessage, setErrorMessage] = useState(() => loadSaved("errorMessage", ""));
  const [configPath, setConfigPath] = useState(() => loadSaved("configPath", ""));
  const [copied, setCopied] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Persist form fields on change
  useEffect(() => { saveField("host", host); }, [host]);
  useEffect(() => { saveField("port", port); }, [port]);
  useEffect(() => { saveField("sshUser", sshUser); }, [sshUser]);
  useEffect(() => { saveField("sshPassword", sshPassword); }, [sshPassword]);
  useEffect(() => { saveField("listenAddress", listenAddress); }, [listenAddress]);
  useEffect(() => { saveField("vpnUsername", vpnUsername); }, [vpnUsername]);
  useEffect(() => { saveField("vpnPassword", vpnPassword); }, [vpnPassword]);
  useEffect(() => { saveField("certType", certType); }, [certType]);
  useEffect(() => { saveField("domain", domain); }, [domain]);
  useEffect(() => { saveField("email", email); }, [email]);
  useEffect(() => { saveField("fetchClientName", fetchClientName); }, [fetchClientName]);

  // Persist deploy state
  useEffect(() => { saveField("deploySteps", JSON.stringify(deploySteps)); }, [deploySteps]);
  useEffect(() => { saveField("deployLogs", JSON.stringify(deployLogs.slice(-200))); }, [deployLogs]);
  useEffect(() => { saveField("configPath", configPath); }, [configPath]);
  useEffect(() => { saveField("errorMessage", errorMessage); }, [errorMessage]);

  const copyLogsToClipboard = () => {
    const text = deployLogs.map((l) => `[${l.level}] ${l.message}`).join("\n");
    const full = errorMessage ? `ERROR: ${errorMessage}\n\n${text}` : text;
    navigator.clipboard.writeText(full).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  useEffect(() => {
    if (logsEndRef.current && showLogs) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [deployLogs, showLogs]);

  useEffect(() => {
    const unlistenStep = listen<DeployStep>("deploy-step", (event) => {
      const { step, status, message } = event.payload;
      setDeploySteps((prev) => ({ ...prev, [step]: { step, status, message } }));

      if (step === "done" && status === "ok") {
        setTimeout(() => setWizardStep("done"), 600);
      }
      if (status === "error") {
        setErrorMessage(message);
        setWizardStep("error");
      }
    });

    const unlistenLog = listen<DeployLog>("deploy-log", (event) => {
      setDeployLogs((prev) => [...prev.slice(-300), event.payload]);
    });

    return () => {
      unlistenStep.then((f) => f());
      unlistenLog.then((f) => f());
    };
  }, []);

  const handleCheckServer = async () => {
    setWizardStep("checking");
    setCheckError("");
    setServerInfo(null);
    try {
      const result = await invoke<{
        installed: boolean;
        version: string;
        serviceActive: boolean;
      }>("check_server_installation", {
        host,
        port: parseInt(port),
        user: sshUser,
        password: sshPassword,
      });
      setServerInfo(result);
      if (result.installed) {
        setWizardStep("found");
      } else {
        setWizardStep("endpoint");
      }
    } catch (e) {
      setCheckError(String(e));
      setWizardStep("found");
      setServerInfo({ installed: false, version: "", serviceActive: false });
    }
  };

  const handleUninstall = async () => {
    setWizardStep("uninstalling");
    setDeploySteps({});
    setDeployLogs([]);
    try {
      await invoke("uninstall_server", {
        host,
        port: parseInt(port),
        user: sshUser,
        password: sshPassword,
      });
      // Auto-disconnect VPN client since server is gone
      invoke("vpn_disconnect").catch(() => {});
      // After uninstall, go to endpoint settings for fresh install
      setTimeout(() => setWizardStep("endpoint"), 800);
    } catch (e) {
      setErrorMessage(String(e));
      setWizardStep("error");
    }
  };

  const handleDeploy = async () => {
    setWizardStep("deploying");
    setDeploySteps({});
    setDeployLogs([]);
    setErrorMessage("");

    try {
      const result = await invoke<string>("deploy_server", {
        host,
        port: parseInt(port),
        user: sshUser,
        password: sshPassword,
        settings: {
          listenAddress,
          vpnUsername,
          vpnPassword,
          certType,
          domain: certType === "letsencrypt" ? domain : "",
          clientName: vpnUsername,
          email: certType === "letsencrypt" ? email : "",
        },
      });
      setConfigPath(result);
    } catch (e) {
      if (wizardStep !== "error") {
        setErrorMessage(String(e));
        setWizardStep("error");
      }
    }
  };

  const handleSkip = async () => {
    const selected = await open({
      multiple: false,
      filters: [{ name: "TrustTunnel Config", extensions: ["toml"] }],
    });
    if (selected) {
      onSetupComplete(selected as string);
    }
  };

  const handleFetchConfig = async () => {
    setWizardStep("fetching");
    setDeploySteps({});
    setDeployLogs([]);
    setErrorMessage("");

    try {
      const result = await invoke<string>("fetch_server_config", {
        host,
        port: parseInt(port),
        user: sshUser,
        password: sshPassword,
        clientName: fetchClientName || vpnUsername || "",
      });
      setConfigPath(result);
      setFetchRetryCount(0);
    } catch (e) {
      setFetchRetryCount((c) => c + 1);
      setErrorMessage(String(e));
      setWizardStep("error");
    }
  };

  const canGoToEndpoint = host.trim().length > 0 && sshPassword.length > 0;
  const canDeploy =
    vpnUsername.trim().length > 0 &&
    vpnPassword.length > 0 &&
    (certType !== "letsencrypt" || (domain.trim().length > 0 && email.trim().length > 0));

  // ─── Step indicator (top bar) ───────────────────
  const stepNumbers: { key: WizardStep; label: string }[] = [
    { key: "server", label: "Сервер" },
    { key: "checking", label: "Проверка" },
    { key: "endpoint", label: "Настройки" },
    { key: "deploying", label: "Установка" },
  ];

  const renderStepBar = () => {
    if (wizardStep === "welcome" || wizardStep === "done" || wizardStep === "error")
      return null;
    const stepMap: Record<string, string> = {
      server: "server",
      checking: "checking",
      found: "checking",
      uninstalling: "checking",
      endpoint: "endpoint",
      deploying: "deploying",
      fetching: "deploying",
    };
    const mapped = stepMap[wizardStep] || wizardStep;
    const currentIdx = stepNumbers.findIndex((s) => s.key === mapped);
    return (
      <div className="flex items-center justify-center gap-2 px-6 pt-4 pb-1">
        {stepNumbers.map((s, i) => (
          <div key={s.key} className="flex items-center gap-2">
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold transition-colors ${
                i < currentIdx
                  ? "bg-emerald-500/20 text-emerald-400"
                  : i === currentIdx
                  ? "bg-indigo-500/30 text-indigo-300 ring-2 ring-indigo-500/50"
                  : "bg-white/5 text-gray-600"
              }`}
            >
              {i < currentIdx ? "✓" : i + 1}
            </div>
            <span
              className={`text-[11px] ${
                i === currentIdx ? "text-gray-300" : "text-gray-600"
              }`}
            >
              {s.label}
            </span>
            {i < stepNumbers.length - 1 && (
              <div
                className={`w-8 h-px ${
                  i < currentIdx ? "bg-emerald-500/40" : "bg-white/10"
                }`}
              />
            )}
          </div>
        ))}
      </div>
    );
  };

  // ─── Welcome ────────────────────────────────────
  if (wizardStep === "welcome") {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-sm w-full text-center space-y-6">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-2xl shadow-indigo-500/30">
            <Shield className="w-8 h-8 text-white" />
          </div>

          <div className="space-y-2">
            <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
              TrustTunnel VPN
            </h1>
            <p className="text-sm text-gray-400 leading-relaxed">
              Быстрый и защищённый VPN-протокол.
              <br />
              Настройте сервер за пару минут или используйте готовый конфиг.
            </p>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => setWizardStep("server")}
              className="w-full btn-primary flex items-center justify-center gap-2 py-3"
            >
              <Server className="w-4 h-4" />
              Настроить сервер
            </button>
            <button
              onClick={() => { saveField("wizardMode", "fetch"); setWizardStep("server"); }}
              className="w-full px-6 py-3 rounded-xl text-sm text-gray-300 hover:text-white
                         border border-indigo-500/30 bg-indigo-500/10 hover:bg-indigo-500/20 transition-all flex items-center justify-center gap-2"
            >
              <Download className="w-4 h-4" />
              Забрать конфиг с сервера
            </button>
            <button
              onClick={handleSkip}
              className="w-full px-6 py-3 rounded-xl text-sm text-gray-400 hover:text-white
                         border border-white/10 hover:bg-white/5 transition-all flex items-center justify-center gap-2"
            >
              <FolderOpen className="w-4 h-4" />
              У меня есть конфиг
            </button>
          </div>

          <div className="text-[11px] text-gray-600 space-y-0.5 pt-2">
            <p>Для настройки сервера потребуется:</p>
            <p>• Linux-сервер (Ubuntu 22+, Debian 11+) с SSH-доступом</p>
            <p>• Права root • Домен, направленный на IP сервера</p>
          </div>
        </div>
      </div>
    );
  }

  // ─── Server Details (SSH) ───────────────────────
  if (wizardStep === "server") {
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="max-w-sm w-full space-y-4">
            <div className="text-center space-y-1">
              <div className="mx-auto w-10 h-10 rounded-xl bg-indigo-500/20 flex items-center justify-center">
                <Server className="w-5 h-5 text-indigo-400" />
              </div>
              <h2 className="text-lg font-bold">Подключение к серверу</h2>
              <p className="text-xs text-gray-500">SSH-данные для доступа к вашему серверу</p>
            </div>

            <div className="space-y-3">
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="block text-[11px] text-gray-500 mb-1">IP-адрес сервера</label>
                  <input
                    type="text"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="123.45.67.89"
                    className="wizard-input !py-2"
                    autoFocus
                  />
                </div>
                <div className="w-20">
                  <label className="block text-[11px] text-gray-500 mb-1">Порт</label>
                  <input
                    type="text"
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    placeholder="22"
                    className="wizard-input !py-2"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] text-gray-500 mb-1">Имя пользователя</label>
                <input
                  type="text"
                  value={sshUser}
                  onChange={(e) => setSshUser(e.target.value)}
                  placeholder="root"
                  className="wizard-input !py-2"
                />
              </div>

              <div>
                <label className="block text-[11px] text-gray-500 mb-1">Пароль SSH</label>
                <div className="relative">
                  <input
                    type={showSshPassword ? "text" : "password"}
                    value={sshPassword}
                    onChange={(e) => setSshPassword(e.target.value)}
                    placeholder="••••••••"
                    className="wizard-input !py-2 pr-10"
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && canGoToEndpoint) {
                        const mode = loadSaved("wizardMode", "") as string;
                        if (mode === "fetch") handleFetchConfig();
                        else handleCheckServer();
                      }
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowSshPassword(!showSshPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  >
                    {showSshPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={() => { saveField("wizardMode", ""); setWizardStep("welcome"); }}
                className="px-4 py-2.5 rounded-xl text-xs text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
              >
                Назад
              </button>
              <button
                onClick={() => {
                  const mode = loadSaved("wizardMode", "") as string;
                  if (mode === "fetch") handleFetchConfig();
                  else handleCheckServer();
                }}
                disabled={!canGoToEndpoint}
                className="flex-1 btn-primary flex items-center justify-center gap-2 !py-2.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {(loadSaved("wizardMode", "") as string) === "fetch" ? "Забрать конфиг" : "Далее"}
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Checking Server ────────────────────────────
  if (wizardStep === "checking") {
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="max-w-sm w-full text-center space-y-5">
            <Loader2 className="w-10 h-10 text-indigo-400 animate-spin mx-auto" />
            <div className="space-y-1">
              <h2 className="text-lg font-bold">Проверяем сервер...</h2>
              <p className="text-xs text-gray-500">
                Подключение по SSH и проверка установленного TrustTunnel
              </p>
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Found: TT already installed ──────────────
  if (wizardStep === "found") {
    const isInstalled = serverInfo?.installed;
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="max-w-sm w-full text-center space-y-5">
            {isInstalled ? (
              <>
                <div className="mx-auto w-14 h-14 rounded-2xl bg-amber-500/20 flex items-center justify-center">
                  <PackageCheck className="w-7 h-7 text-amber-400" />
                </div>
                <div className="space-y-1.5">
                  <h2 className="text-lg font-bold text-amber-300">
                    TrustTunnel уже установлен
                  </h2>
                  {serverInfo?.version && (
                    <p className="text-xs text-gray-500">
                      Версия: {serverInfo.version}
                    </p>
                  )}
                  <p className="text-xs text-gray-400">
                    Сервис: {serverInfo?.serviceActive ? (
                      <span className="text-emerald-400">работает</span>
                    ) : (
                      <span className="text-gray-500">не запущен</span>
                    )}
                  </p>
                </div>

                <div className="space-y-2">
                  <button
                    onClick={handleFetchConfig}
                    className="w-full btn-primary flex items-center justify-center gap-2 py-3"
                  >
                    <Download className="w-4 h-4" />
                    Забрать конфиг с сервера
                  </button>
                  {confirmUninstall ? (
                    <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 space-y-2.5">
                      <p className="text-xs text-red-300 font-medium text-center">
                        Вы уверены? Это действие необратимо.
                      </p>
                      <p className="text-[10px] text-red-300/60 text-center leading-relaxed">
                        Сервис будет остановлен, все файлы TrustTunnel будут удалены с сервера.
                        Текущее VPN-подключение будет разорвано.
                      </p>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setConfirmUninstall(false)}
                          className="flex-1 px-3 py-2 rounded-xl text-xs text-gray-400
                                     border border-white/10 hover:bg-white/5 transition-all"
                        >
                          Отмена
                        </button>
                        <button
                          onClick={() => { setConfirmUninstall(false); handleUninstall(); }}
                          className="flex-1 px-3 py-2 rounded-xl text-xs font-medium
                                     bg-red-500/30 border border-red-500/50 text-red-300 hover:bg-red-500/40 transition-all"
                        >
                          Да, удалить
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmUninstall(true)}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm font-medium
                                 bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition-all"
                    >
                      <Trash2 className="w-4 h-4" />
                      Удалить и переустановить
                    </button>
                  )}
                  <button
                    onClick={handleSkip}
                    className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm
                               text-gray-400 hover:text-white border border-white/10 hover:bg-white/5 transition-all"
                  >
                    <SkipForward className="w-4 h-4" />
                    Пропустить — у меня есть конфиг
                  </button>
                  <button
                    onClick={() => setWizardStep("endpoint")}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs
                               text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    Переустановить поверх (без удаления)
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="mx-auto w-14 h-14 rounded-2xl bg-indigo-500/20 flex items-center justify-center">
                  <Server className="w-7 h-7 text-indigo-400" />
                </div>
                <div className="space-y-1.5">
                  <h2 className="text-lg font-bold">Сервер готов к настройке</h2>
                  <p className="text-xs text-gray-500">
                    TrustTunnel не обнаружен — можно установить с нуля
                  </p>
                  {checkError && (
                    <p className="text-[10px] text-amber-400 mt-1">
                      Предупреждение: {checkError}
                    </p>
                  )}
                </div>
                <button
                  onClick={() => setWizardStep("endpoint")}
                  className="btn-primary inline-flex items-center gap-2 px-6 py-3"
                >
                  Продолжить настройку
                  <ChevronRight className="w-4 h-4" />
                </button>
              </>
            )}

            <button
              onClick={() => setWizardStep("server")}
              className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              ← Назад к SSH
            </button>
          </div>
        </div>
      </>
    );
  }

  // ─── Uninstalling ─────────────────────────────
  if (wizardStep === "uninstalling") {
    const step = deploySteps["uninstall"];
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="max-w-sm w-full text-center space-y-5">
            {step?.status === "ok" ? (
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
            ) : (
              <Loader2 className="w-10 h-10 text-red-400 animate-spin mx-auto" />
            )}
            <div className="space-y-1">
              <h2 className="text-lg font-bold">
                {step?.status === "ok"
                  ? "TrustTunnel удалён"
                  : "Удаление TrustTunnel..."}
              </h2>
              <p className="text-xs text-gray-500">
                {step?.message || "Останавливаем сервис и удаляем файлы..."}
              </p>
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Endpoint Settings ──────────────────────────
  if (wizardStep === "endpoint") {
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex items-center justify-center p-4 overflow-y-auto">
          <div className="max-w-sm w-full space-y-3">
            <div className="text-center space-y-1">
              <div className="mx-auto w-10 h-10 rounded-xl bg-purple-500/20 flex items-center justify-center">
                <Settings className="w-5 h-5 text-purple-400" />
              </div>
              <h2 className="text-lg font-bold">Настройки VPN</h2>
            </div>

            {/* VPN Credentials */}
            <div className="glass-card p-3 space-y-2">
              <div className="flex items-center gap-1.5 text-[11px] text-gray-400 font-semibold uppercase tracking-wider">
                <User className="w-3 h-3" />
                Учётные данные VPN
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] text-gray-500 mb-1">Логин</label>
                  <input
                    type="text"
                    value={vpnUsername}
                    onChange={(e) => setVpnUsername(e.target.value)}
                    placeholder="vpnuser"
                    className="wizard-input !py-2 !text-xs"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-gray-500 mb-1">Пароль</label>
                  <div className="relative">
                    <input
                      type={showVpnPassword ? "text" : "password"}
                      value={vpnPassword}
                      onChange={(e) => setVpnPassword(e.target.value)}
                      placeholder="••••••••"
                      className="wizard-input !py-2 !text-xs pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowVpnPassword(!showVpnPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    >
                      {showVpnPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Certificate */}
            <div className="glass-card p-3 space-y-2">
              <div className="flex items-center gap-1.5 text-[11px] text-gray-400 font-semibold uppercase tracking-wider">
                <Lock className="w-3 h-3" />
                TLS-сертификат
              </div>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setCertType("letsencrypt")}
                  className={`p-2.5 rounded-xl text-xs text-left transition-all border ${
                    certType === "letsencrypt"
                      ? "border-emerald-500/50 bg-emerald-500/10 text-white"
                      : "border-white/10 bg-white/5 text-gray-400 hover:bg-white/10"
                  }`}
                >
                  <div className="font-medium flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    Let's Encrypt
                  </div>
                  <div className="text-[10px] text-gray-500 mt-0.5">Рекомендуется</div>
                </button>
                <button
                  onClick={() => setCertType("selfsigned")}
                  className={`p-2.5 rounded-xl text-xs text-left transition-all border ${
                    certType === "selfsigned"
                      ? "border-amber-500/50 bg-amber-500/10 text-white"
                      : "border-white/10 bg-white/5 text-gray-400 hover:bg-white/10"
                  }`}
                >
                  <div className="font-medium">Самоподписанный</div>
                  <div className="text-[10px] text-gray-500 mt-0.5">Только для тестов</div>
                </button>
              </div>

              {certType === "selfsigned" && (
                <div className="flex items-start gap-2 p-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <p className="text-[10px] text-amber-300 leading-relaxed">
                    Самоподписанный сертификат небезопасен и может быть заблокирован.
                    Настоятельно рекомендуем использовать домен с Let's Encrypt.
                  </p>
                </div>
              )}

              {certType === "letsencrypt" && (
                <div className="space-y-2">
                  <div>
                    <label className="block text-[11px] text-gray-500 mb-1">Доменное имя</label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-600" />
                      <input
                        type="text"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        placeholder="vpn.example.com"
                        className="wizard-input !py-2 !text-xs pl-9"
                      />
                    </div>
                    <p className="text-[10px] text-gray-600 mt-0.5">
                      A-запись домена → {host || "IP сервера"}, порт 80 открыт
                    </p>
                  </div>
                  <div>
                    <label className="block text-[11px] text-gray-500 mb-1">Email для уведомлений</label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-600" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="you@example.com"
                        className="wizard-input !py-2 !text-xs pl-9"
                      />
                    </div>
                    <p className="text-[10px] text-gray-600 mt-0.5">
                      Для уведомлений об обновлении сертификата
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Advanced settings (collapsed) */}
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
            >
              {showAdvanced ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              Дополнительные настройки
            </button>
            {showAdvanced && (
              <div className="glass-card p-3">
                <label className="block text-[11px] text-gray-500 mb-1">Адрес прослушивания</label>
                <input
                  type="text"
                  value={listenAddress}
                  onChange={(e) => setListenAddress(e.target.value)}
                  placeholder="0.0.0.0:443"
                  className="wizard-input !py-2 !text-xs"
                />
                <p className="text-[10px] text-gray-600 mt-0.5">
                  Оставьте по умолчанию, если не уверены
                </p>
              </div>
            )}

            {/* System requirements info */}
            <div className="flex items-start gap-2 p-2 rounded-lg bg-indigo-500/5 border border-indigo-500/10">
              <Info className="w-3.5 h-3.5 text-indigo-400 shrink-0 mt-0.5" />
              <div className="text-[10px] text-gray-500 leading-relaxed">
                <span className="text-gray-400">Требования:</span> Linux x86_64, 512 MB RAM, 100 MB диска, порт 443
                {certType === "letsencrypt" && " + порт 80"}
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={() => setWizardStep("server")}
                className="px-4 py-2.5 rounded-xl text-xs text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
              >
                Назад
              </button>
              <button
                onClick={handleDeploy}
                disabled={!canDeploy}
                className="flex-1 btn-primary flex items-center justify-center gap-2 !py-2.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Rocket className="w-4 h-4" />
                Установить
              </button>
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Deploying ──────────────────────────────────
  if (wizardStep === "deploying") {
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex flex-col items-center justify-center p-6">
          <div className="max-w-md w-full space-y-4">
            <div className="text-center space-y-1">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
              <h2 className="text-lg font-bold">Устанавливаем TrustTunnel...</h2>
              <p className="text-xs text-gray-500">Это может занять несколько минут</p>
            </div>

            <div className="glass-card p-4 space-y-2">
              {STEPS_ORDER.map((stepId) => {
                const step = deploySteps[stepId];
                if (!step) {
                  return (
                    <div key={stepId} className="flex items-center gap-2.5 text-gray-600">
                      <div className="w-4 h-4 rounded-full border border-gray-700/50 shrink-0" />
                      <span className="text-xs">{STEP_LABELS[stepId]}</span>
                    </div>
                  );
                }
                return (
                  <div key={stepId} className="flex items-center gap-2.5">
                    {step.status === "progress" && (
                      <Loader2 className="w-4 h-4 text-amber-400 animate-spin shrink-0" />
                    )}
                    {step.status === "ok" && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    {step.status === "error" && (
                      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                    )}
                    <span
                      className={`text-xs ${
                        step.status === "progress"
                          ? "text-amber-300"
                          : step.status === "ok"
                          ? "text-emerald-300"
                          : "text-red-300"
                      }`}
                    >
                      {step.message}
                    </span>
                  </div>
                );
              })}
            </div>

            <div>
              <button
                onClick={() => setShowLogs(!showLogs)}
                className="flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
              >
                {showLogs ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                {showLogs ? "Скрыть детали" : "Показать детали"}
                <span className="text-gray-700">({deployLogs.length})</span>
              </button>

              {showLogs && (
                <div className="mt-1.5 glass-card p-2.5 max-h-36 overflow-y-auto font-mono text-[10px] space-y-0.5 select-text cursor-text relative group">
                  <button
                    onClick={copyLogsToClipboard}
                    className="absolute top-1.5 right-1.5 p-1 rounded-lg bg-white/10 hover:bg-white/20 text-gray-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                    title="Копировать логи"
                  >
                    {copied ? <ClipboardCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                  {deployLogs.map((log, i) => (
                    <div
                      key={i}
                      className={
                        log.level === "warn"
                          ? "text-amber-400/80"
                          : log.level === "error"
                          ? "text-red-400/80"
                          : "text-gray-500"
                      }
                    >
                      {log.message}
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              )}
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Fetching config from server ─────────────────
  if (wizardStep === "fetching") {
    const FETCH_STEPS_ORDER = ["connect", "auth", "check", "export", "save", "done"];
    const FETCH_STEP_LABELS: Record<string, string> = {
      connect: "Подключение к серверу",
      auth: "Авторизация",
      check: "Проверка TrustTunnel",
      export: "Экспорт конфига",
      save: "Сохранение",
      done: "Готово",
    };
    return (
      <>
        {renderStepBar()}
        <div className="flex-1 flex flex-col items-center justify-center p-6">
          <div className="max-w-md w-full space-y-4">
            <div className="text-center space-y-1">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
              <h2 className="text-lg font-bold">Получаем конфиг с сервера...</h2>
              <p className="text-xs text-gray-500">Подключаемся и экспортируем клиентскую конфигурацию</p>
            </div>

            <div className="glass-card p-4 space-y-2">
              {FETCH_STEPS_ORDER.map((stepId) => {
                const step = deploySteps[stepId];
                if (!step) {
                  return (
                    <div key={stepId} className="flex items-center gap-2.5 text-gray-600">
                      <div className="w-4 h-4 rounded-full border border-gray-700/50 shrink-0" />
                      <span className="text-xs">{FETCH_STEP_LABELS[stepId]}</span>
                    </div>
                  );
                }
                return (
                  <div key={stepId} className="flex items-center gap-2.5">
                    {step.status === "progress" && (
                      <Loader2 className="w-4 h-4 text-amber-400 animate-spin shrink-0" />
                    )}
                    {step.status === "ok" && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    {step.status === "error" && (
                      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                    )}
                    <span
                      className={`text-xs ${
                        step.status === "progress"
                          ? "text-amber-300"
                          : step.status === "ok"
                          ? "text-emerald-300"
                          : "text-red-300"
                      }`}
                    >
                      {step.message}
                    </span>
                  </div>
                );
              })}
            </div>

            <div>
              <button
                onClick={() => setShowLogs(!showLogs)}
                className="flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
              >
                {showLogs ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                {showLogs ? "Скрыть детали" : "Показать детали"}
                <span className="text-gray-700">({deployLogs.length})</span>
              </button>

              {showLogs && (
                <div className="mt-1.5 glass-card p-2.5 max-h-36 overflow-y-auto font-mono text-[10px] space-y-0.5 select-text cursor-text relative group">
                  <button
                    onClick={copyLogsToClipboard}
                    className="absolute top-1.5 right-1.5 p-1 rounded-lg bg-white/10 hover:bg-white/20 text-gray-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                    title="Копировать логи"
                  >
                    {copied ? <ClipboardCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                  {deployLogs.map((log, i) => (
                    <div
                      key={i}
                      className={
                        log.level === "warn"
                          ? "text-amber-400/80"
                          : log.level === "error"
                          ? "text-red-400/80"
                          : "text-gray-500"
                      }
                    >
                      {log.message}
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              )}
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─── Done ───────────────────────────────────────
  if (wizardStep === "done") {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-sm w-full text-center space-y-5">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-green-600 flex items-center justify-center shadow-2xl shadow-emerald-500/30">
            <CheckCircle2 className="w-8 h-8 text-white" />
          </div>

          <div className="space-y-1.5">
            <h2 className="text-xl font-bold text-emerald-300">Всё готово!</h2>
            <p className="text-sm text-gray-400">
              Сервер установлен и запущен. Конфигурация создана автоматически.
            </p>
          </div>

          {configPath && (
            <div className="glass-card p-3 text-left">
              <p className="text-[11px] text-gray-500 mb-0.5">Файл конфигурации:</p>
              <p className="text-xs text-gray-300 font-mono break-all">{configPath}</p>
            </div>
          )}

          <div className="flex flex-col gap-2 items-center">
            <button
              onClick={() => { setWizardStep("welcome"); onSetupComplete(configPath); }}
              className="btn-primary inline-flex items-center gap-2 px-6 py-3"
            >
              Перейти к подключению
              <ChevronRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => setWizardStep("welcome")}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              ← На главную
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Error ──────────────────────────────────────
  if (wizardStep === "error") {
    const isFetchMode = (loadSaved("wizardMode", "") as string) === "fetch";
    const showReinstallPrompt = isFetchMode && fetchRetryCount >= 2;

    return (
      <div className="flex-1 flex flex-col items-center overflow-y-auto p-6">
        <div className="max-w-sm w-full text-center space-y-4 my-auto">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500 to-rose-600 flex items-center justify-center shadow-2xl shadow-red-500/30 shrink-0">
            <XCircle className="w-8 h-8 text-white" />
          </div>

          <div className="space-y-1.5">
            <h2 className="text-xl font-bold text-red-300">Что-то пошло не так</h2>
            <div className="max-h-32 overflow-y-auto rounded-lg bg-white/5 p-2">
              <p className="text-xs text-gray-400 leading-relaxed select-text cursor-text break-words">
                {errorMessage || "Неизвестная ошибка"}
              </p>
            </div>
          </div>

          {deployLogs.length > 0 && (
            <div>
              <button
                onClick={() => setShowLogs(!showLogs)}
                className="flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors mx-auto"
              >
                {showLogs ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                {showLogs ? "Скрыть логи" : "Показать логи"}
              </button>
              {showLogs && (
                <div className="mt-1.5 glass-card p-2.5 max-h-36 overflow-y-auto font-mono text-[10px] space-y-0.5 text-left select-text cursor-text relative group">
                  <button
                    onClick={copyLogsToClipboard}
                    className="absolute top-1.5 right-1.5 p-1 rounded-lg bg-white/10 hover:bg-white/20 text-gray-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                    title="Копировать логи"
                  >
                    {copied ? <ClipboardCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                  {deployLogs.map((log, i) => (
                    <div
                      key={i}
                      className={log.level === "error" ? "text-red-400/80" : "text-gray-500"}
                    >
                      {log.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {showReinstallPrompt ? (
            <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 space-y-2.5">
              <p className="text-xs text-amber-300 font-medium">
                Хотите переустановить VPN на сервере?
              </p>
              <p className="text-[10px] text-amber-300/60 leading-relaxed">
                Копирование конфига не удалось повторно. Можно переустановить VPN с нуля.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setWizardStep("server")}
                  className="flex-1 px-3 py-2 rounded-xl text-xs text-gray-400
                             border border-white/10 hover:bg-white/5 transition-all"
                >
                  Отмена
                </button>
                <button
                  onClick={() => { setFetchRetryCount(0); saveField("wizardMode", ""); setWizardStep("endpoint"); }}
                  className="flex-1 px-3 py-2 rounded-xl text-xs font-medium
                             bg-amber-500/20 border border-amber-500/40 text-amber-300 hover:bg-amber-500/30 transition-all"
                >
                  Да, переустановить
                </button>
              </div>
            </div>
          ) : (
            <div className="flex gap-2 justify-center">
              <button
                onClick={() => setWizardStep(isFetchMode ? "server" : "endpoint")}
                className="px-4 py-2.5 rounded-xl text-xs text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
              >
                {isFetchMode ? "Назад" : "Назад к настройкам"}
              </button>
              <button
                onClick={isFetchMode ? handleFetchConfig : handleDeploy}
                className="btn-primary !py-2.5 text-sm"
              >
                Попробовать снова
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  return null;
}

export default SetupWizard;
