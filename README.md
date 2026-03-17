<!-- markdownlint-disable MD041 -->
<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<h2 align="center">TrustTunnel Client for Windows</h2>

<p align="center">
Графический клиент для подключения к VPN-серверам на базе протокола TrustTunnel.<br>
Автоматически разворачивает сервер на удалённой машине через SSH и подключается к нему.
</p>

<p align="center">
  <a href="https://github.com/ialexbond/TrustTunnelClient/releases">Скачать</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnel">TrustTunnel Endpoint</a>
  · <a href="#быстрый-старт">Быстрый старт</a>
</p>

---

## Что такое TrustTunnel

**TrustTunnel** — VPN-протокол, разработанный компанией [AdGuard](https://adguard.com).
Протокол маскирует VPN-трафик под обычные HTTPS-запросы (HTTP/1.1, HTTP/2, QUIC),
что делает его устойчивым к блокировкам со стороны DPI и государственных фильтров.

Ключевые характеристики протокола:

- Туннелирование TCP, UDP и ICMP трафика
- Маскировка под обычный веб-трафик
- Поддержка системного туннеля (TUN) и SOCKS5-прокси
- Split tunneling — раздельная маршрутизация трафика
- Пользовательские DNS-серверы через VPN

## Что делает этот клиент

**TrustTunnel Client for Windows** — это графическое desktop-приложение,
которое позволяет:

1. **Автоматически развернуть** VPN-сервер TrustTunnel на удалённом Linux-сервере
   через SSH (нужен только IP, логин и пароль)
2. **Подключиться** к развёрнутому серверу одним нажатием кнопки
3. **Управлять** VPN-подключением через удобный GUI с мониторингом состояния и логами

Приложение работает в **портативном режиме** — не требует установки,
все данные хранятся рядом с исполняемым файлом.

---

## Быстрый старт

### Что нужно

- **Windows 10/11** (x64)
- **Удалённый Linux-сервер** с root-доступом по SSH (Ubuntu 20.04+, Debian 11+)
  — например VPS от любого хостинг-провайдера

### Использование

1. Скачайте архив `TrustTunnel-v*-portable-win64.zip`
   из [Releases](https://github.com/ialexbond/TrustTunnelClient/releases)
2. Распакуйте в любую папку
3. Запустите `TrustTunnel.exe` (потребуются права администратора — WinTUN нуждается в них)
4. В мастере настройки введите данные SSH-сервера (IP, порт, логин, пароль)
5. Приложение автоматически установит TrustTunnel-сервер и создаст конфигурацию
6. Нажмите «Подключиться» — готово

---

## Архитектура

```text
┌──────────────────────────────────────────────────┐
│  TrustTunnel.exe (Tauri v2 + React + Tailwind)   │
│  └── GUI: настройка, подключение, логи, трей     │
│      │                                           │
│      ├── SSH Deploy (Rust) ──► удалённый сервер  │
│      │   установка endpoint через SSH            │
│      │                                           │
│      └── Sidecar: trusttunnel_client.exe (C++)   │
│          VPN-подключение через WinTUN             │
└──────────────────────────────────────────────────┘
```

- **Frontend**: React + TypeScript + Tailwind CSS
- **Backend**: Rust (Tauri v2) — управление sidecar-процессом,
  SSH-деплой сервера, системный трей
- **VPN-ядро**: C++ библиотеки TrustTunnel — сетевой стек,
  туннелирование, WinTUN-адаптер

---

## Сборка из исходников

### Требования

- **Node.js** >= 18
- **Rust** >= 1.75
- **CMake** >= 3.24
- **Visual Studio 2022** (C++ Build Tools)
- **Python** >= 3.10 (для Conan)

### Шаги

```bash
# 1. Клонировать репозиторий
git clone https://github.com/ialexbond/TrustTunnelClient.git
cd TrustTunnelClient

# 2. Собрать C++ sidecar (из корня проекта)
build_client.bat

# 3. Скопировать бинарник в папку Tauri sidecar
copy build\trusttunnel\Release\trusttunnel_client.exe ^
     gui-app\src-tauri\binaries\trusttunnel_client-x86_64-pc-windows-msvc.exe

# 4. Установить JS-зависимости и собрать GUI
cd gui-app
npm install
npm run tauri build
```

Готовый exe: `gui-app/src-tauri/target/release/trusttunnel-gui.exe`

### Создание портативного архива

```powershell
$rel = "gui-app\src-tauri\target\release"
mkdir TrustTunnel-Portable
Copy-Item "$rel\trusttunnel-gui.exe"   "TrustTunnel-Portable\TrustTunnel.exe"
Copy-Item "$rel\trusttunnel_client.exe" "TrustTunnel-Portable\"
Copy-Item "$rel\wintun.dll"            "TrustTunnel-Portable\"
Copy-Item "$rel\vcruntime140.dll"      "TrustTunnel-Portable\"
Copy-Item "$rel\vcruntime140_1.dll"    "TrustTunnel-Portable\"
Compress-Archive "TrustTunnel-Portable\*" "TrustTunnel-portable-win64.zip"
```

---

## Известные проблемы

- **Только Windows** — на данный момент GUI-клиент поддерживает только Windows.
  C++ ядро кроссплатформенное, но GUI обёртка заточена под Windows (WinTUN, UAC, системный трей).
- **Требуются права администратора** — WinTUN-адаптер требует admin-привилегий
  для создания виртуального сетевого интерфейса.
- **Один экземпляр** — при попытке запуска второй копии приложения
  первое окно будет активировано вместо создания дубликата.

---

## Планы развития

- [ ] Linux-версия клиента
- [ ] macOS-версия клиента
- [ ] Автообновление приложения
- [ ] Поддержка нескольких серверов / профилей
- [ ] Killswitch (блокировка трафика при разрыве VPN)
- [ ] Split tunneling в GUI (выбор приложений/сайтов)

---

## Технологии

| Компонент | Технология |
|---|---|
| GUI Framework | [Tauri v2](https://v2.tauri.app) |
| Frontend | React + TypeScript + Tailwind CSS |
| Backend | Rust |
| VPN Core | C++ (TrustTunnel Client Libraries) |
| Tunnel Driver | [WinTUN](https://www.wintun.net) |
| SSH Deploy | [russh](https://github.com/warp-tech/russh) |

---

## Благодарности

- [AdGuard](https://adguard.com) — за разработку протокола TrustTunnel
  и открытие исходного кода клиентских библиотек
- Клиентское приложение создано методом **вайб-кодинга** —
  AI-ассистент писал код на основе описания задач на естественном языке

---

## Лицензия

[Apache 2.0](LICENSE)

---

## Ссылки

- [TrustTunnel Endpoint](https://github.com/TrustTunnel/TrustTunnel) —
  серверная часть протокола
- [TrustTunnel CLI Client](trusttunnel/README.md) —
  справка по консольному клиенту (C++)
