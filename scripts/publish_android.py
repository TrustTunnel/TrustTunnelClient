#!/usr/bin/env python3
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def log(msg):
    print(msg, flush=True)


def run(cmd, cwd=None, env=None, check=True, **kwargs):
    if isinstance(cmd, (list, tuple)):
        log("> " + " ".join(str(c) for c in cmd))
    else:
        log("> " + str(cmd))
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, **kwargs)


def is_windows():
    return os.name == "nt"


def venv_python(venv_dir):
    if is_windows():
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_venv(venv_dir):
    vpy = venv_python(venv_dir)
    if not vpy.exists():
        run([sys.executable, "-m", "venv", str(venv_dir)])
    return vpy


def ensure_pip_and_deps(vpy, requirements):
    run([str(vpy), "-m", "pip", "install", "--upgrade", "pip"])
    run([str(vpy), "-m", "pip", "install", "-r", str(requirements)])
    run([str(vpy), "-m", "pip", "install", "conan"])


def add_to_path(env, path):
    env["PATH"] = str(path) + os.pathsep + env.get("PATH", "")


def ensure_git(env):
    try:
        run(["git", "--version"], env=env)
    except Exception:
        if is_windows() and shutil.which("winget", path=env.get("PATH", "")):
            run(["winget", "install", "-e", "--id", "Git.Git", "--silent"], env=env)
            run(["git", "--version"], env=env)
        else:
            raise RuntimeError("git not found in PATH")


def install_rustup_windows(env):
    rustup_url = "https://win.rustup.rs/x86_64"
    rustup_exe = Path(tempfile.gettempdir()) / "rustup-init.exe"
    log("Downloading rustup-init.exe...")
    urllib.request.urlretrieve(rustup_url, rustup_exe)
    run([str(rustup_exe), "-y"], env=env)
    cargo_bin = Path.home() / ".cargo" / "bin"
    add_to_path(env, cargo_bin)


def ensure_rustup(env):
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.exists():
        add_to_path(env, cargo_bin)
    if shutil.which("rustup", path=env.get("PATH", "")) is None:
        if is_windows():
            install_rustup_windows(env)
        else:
            raise RuntimeError("rustup not found; install rustup and retry")
    run(["rustup", "--version"], env=env)


def ensure_cargo_and_ndk(env):
    ensure_rustup(env)
    if shutil.which("cargo", path=env.get("PATH", "")) is None:
        if is_windows():
            install_rustup_windows(env)
        else:
            raise RuntimeError("cargo not found; install rustup and retry")
    run(["cargo", "--version"], env=env)
    try:
        run(["cargo", "ndk", "--version"], env=env)
    except Exception:
        run(["cargo", "install", "cargo-ndk"], env=env)
        run(["cargo", "ndk", "--version"], env=env)


def read_rust_toolchain(root):
    toml_path = root / "rust-toolchain.toml"
    if toml_path.exists():
        for raw in toml_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', raw)
            if match:
                return match.group(1)
    legacy_path = root / "rust-toolchain"
    if legacy_path.exists():
        for raw in legacy_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                return line
    return None


def ensure_rust_toolchain(env, toolchain):
    if not toolchain:
        return None
    log(f"Ensuring Rust toolchain {toolchain} is installed...")
    run(["rustup", "toolchain", "install", toolchain], env=env)
    return toolchain


def ensure_rust_targets(env, toolchain=None):
    required_targets = {
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "i686-linux-android",
        "x86_64-linux-android",
    }
    
    log("Checking installed Rust targets...")
    cmd = ["rustup", "target", "list", "--installed"]
    if toolchain:
        cmd += ["--toolchain", toolchain]
    result = run(
        cmd, 
        env=env, 
        check=True, 
        stdout=subprocess.PIPE
    )
    installed_targets = set(result.stdout.decode().splitlines())
    
    missing_targets = sorted(required_targets - installed_targets)
    
    if missing_targets:
        log(f"Installing missing Rust targets: {', '.join(missing_targets)}")
        cmd = ["rustup", "target", "add"]
        if toolchain:
            cmd += ["--toolchain", toolchain]
        cmd += list(missing_targets)
        run(cmd, env=env)
    else:
        log("All required Android Rust targets are installed.")


def parse_version(text):
    parts = []
    for piece in text.replace("-", ".").split("."):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            break
    return parts


def find_android_sdk_root():
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        val = os.environ.get(var)
        if val:
            return Path(val)
    if is_windows():
        local = os.environ.get("LOCALAPPDATA")
        if local:
            sdk = Path(local) / "Android" / "Sdk"
            if sdk.exists():
                return sdk
    return None


def find_android_cmake_root(sdk_root, preferred_version=None):
    cmake_root = sdk_root / "cmake"
    if not cmake_root.exists():
        return None
    versions = [p for p in cmake_root.iterdir() if p.is_dir()]
    if not versions:
        return None
    if preferred_version:
        for ver in versions:
            if ver.name == preferred_version:
                return ver
    versions.sort(key=lambda p: parse_version(p.name))
    return versions[-1]


def upsert_property(path, key, value):
    line = f"{key}={value}"
    if not path.exists():
        path.write_text(line + "\n", encoding="utf-8")
        return
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for i, existing in enumerate(lines):
        if existing.strip().startswith(f"{key}="):
            lines[i] = line
            break
    else:
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_gradle_cmake_version(android_dir):
    gradle_file = android_dir / "lib" / "build.gradle.kts"
    if not gradle_file.exists():
        return None
    in_cmake = False
    for raw in gradle_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("cmake {"):
            in_cmake = True
            continue
        if in_cmake and line.startswith("}"):
            in_cmake = False
            continue
        if in_cmake:
            match = re.search(r'version\s*=\s*"([^"]+)"', line)
            if match:
                return match.group(1)
    return None


def ensure_android_sdk(env, android_dir):
    sdk_root = find_android_sdk_root()
    if not sdk_root:
        raise RuntimeError("Android SDK not found; install it with Android Studio")
    env.setdefault("ANDROID_SDK_ROOT", str(sdk_root))
    env.setdefault("ANDROID_HOME", str(sdk_root))
    local_props = android_dir / "local.properties"
    if not local_props.exists():
        local_props.parent.mkdir(parents=True, exist_ok=True)
    if "sdk.dir" not in read_gradle_properties(local_props):
        upsert_property(local_props, "sdk.dir", sdk_root.as_posix())
    return sdk_root, local_props


def ensure_cmake(env, android_dir):
    sdk_root, local_props = ensure_android_sdk(env, android_dir)
    preferred_version = get_gradle_cmake_version(android_dir)
    cmake_root = find_android_cmake_root(sdk_root, preferred_version)
    if not cmake_root:
        raise RuntimeError("CMake not found in Android SDK; install CMake in SDK Manager")
    cmake_bin = cmake_root / "bin"
    add_to_path(env, cmake_bin)
    upsert_property(local_props, "cmake.dir", cmake_root.as_posix())
    if preferred_version and cmake_root.name != preferred_version:
        log(f"Warning: Gradle expects CMake {preferred_version}, using {cmake_root.name}")


def ensure_java(env):
    if "JAVA_HOME" in env:
        return
    if is_windows():
        jbr = Path(r"C:\Program Files\Android\Android Studio\jbr")
        if jbr.exists():
            env["JAVA_HOME"] = str(jbr)
            add_to_path(env, jbr / "bin")


def read_gradle_properties(path):
    props = {}
    if not path.exists():
        return props
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        props[key.strip()] = val.strip()
    return props


def ensure_gpr_credentials():
    gradle_props = Path.home() / ".gradle" / "gradle.properties"
    props = read_gradle_properties(gradle_props)
    if "gpr.user" in props and "gpr.key" in props:
        return

    log("Missing GitHub Package Registry (GPR) credentials in ~/.gradle/gradle.properties.")
    log("Please enter your GitHub credentials to configure them now.")
    
    user = input("GitHub Username: ").strip()
    while not user:
        user = input("GitHub Username: ").strip()
        
    token = input("GitHub Personal Access Token (PAT): ").strip()
    while not token:
        token = input("GitHub Personal Access Token (PAT): ").strip()
        
    if not gradle_props.parent.exists():
        gradle_props.parent.mkdir(parents=True, exist_ok=True)
        
    upsert_property(gradle_props, "gpr.user", user)
    upsert_property(gradle_props, "gpr.key", token)
    log(f"Credentials saved to {gradle_props}")


def main():
    root = Path(__file__).resolve().parent.parent
    android_dir = root / "platform" / "android"
    requirements = root / "scripts" / "requirements.txt"
    venv_dir = root / "env"

    env = os.environ.copy()

    vpy = ensure_venv(venv_dir)
    ensure_pip_and_deps(vpy, requirements)

    venv_scripts = vpy.parent
    add_to_path(env, venv_scripts)

    ensure_git(env)
    ensure_java(env)
    ensure_cmake(env, android_dir)
    ensure_cargo_and_ndk(env)
    toolchain = read_rust_toolchain(root)
    if toolchain:
        ensure_rust_toolchain(env, toolchain)
        env["RUSTUP_TOOLCHAIN"] = toolchain
    ensure_rust_targets(env, toolchain)
    ensure_gpr_credentials()

    run([str(vpy), str(root / "scripts" / "bootstrap_conan_deps.py")], env=env, cwd=str(root))

    cxx_dir = android_dir / "lib" / ".cxx"
    if cxx_dir.exists():
        shutil.rmtree(cxx_dir, ignore_errors=True)

    if is_windows():
        run(["cmd", "/c", "gradlew.bat --stop"], cwd=str(android_dir), env=env, check=False)
        run(["cmd", "/c", "gradlew.bat :lib:publish --no-daemon --info"], cwd=str(android_dir), env=env)
    else:
        run(["./gradlew", "--stop"], cwd=str(android_dir), env=env, check=False)
        run(["./gradlew", ":lib:publish", "--no-daemon", "--info"], cwd=str(android_dir), env=env)

    log("Publish completed.")


if __name__ == "__main__":
    main()
