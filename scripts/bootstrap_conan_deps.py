#!/usr/bin/env python3

"""
This script intended to fill the local conan cache with the packages required
for building the project. Clean build scenario requires running this script
before running the cmake command. Besides that, it may be also required after
the dependencies updates.

Usage:
    bootstrap_conan_deps.py [nlc_url [dns_libs_url]]

`nlc_url` is the URL of AdGuard's NativeLibsCommon repository
(defaults to https://github.com/AdguardTeam/NativeLibsCommon.git).
`nlc_url` is the URL of AdGuard's DnsLibs repository
(defaults to https://github.com/AdguardTeam/DnsLibs.git).
"""

import os
import shutil
import stat
import subprocess
import sys
import yaml

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)
nlc_url = sys.argv[1] if len(sys.argv) > 1 else 'https://github.com/AdguardTeam/NativeLibsCommon.git'
nlc_dir_name = "native-libs-common"
dns_libs_url = sys.argv[2] if len(sys.argv) > 2 else 'https://github.com/AdguardTeam/DnsLibs.git'
dns_libs_dir_name = "dns-libs"
nlc_versions = []


def on_rm_tree_error(func, path, _):
    """
    Workaround for Windows behavior, where `shutil.rmtree`
    fails with an access error (read only file).
    So, attempt to add write permission and try again.
    """
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


def robust_clone(url, path):
    """
    Clones the repo if not exists, or updates it if it does.
    If update/delete fails, it tries to proceed.
    """
    if os.path.exists(path):
        try:
            shutil.rmtree(path, onerror=on_rm_tree_error)
        except OSError:
            print(f"Warning: Could not remove {path}, attempting to update existing repo...")
            pass
    
    if not os.path.exists(path):
        subprocess.run(["git", "clone", url, path], check=True)
    else:
        # If we couldn't delete it, update it
        try:
            subprocess.run(["git", "fetch", "--all"], cwd=path, check=True)
        except subprocess.CalledProcessError:
            print(f"Warning: Failed to fetch {path}, proceeding anyway...")


with open(os.path.join(project_dir, "conanfile.py"), "r") as file:
    for line in map(str.strip, file.readlines()):
        if line.startswith('self.requires("native_libs_common/') \
                and ('@adguard/oss"' in line):
            nlc_versions.append(line.split('@')[0].split('/')[1])
        elif line.startswith('self.requires("dns-libs/') \
                and ('@adguard/oss"' in line):
            dns_libs_version = line.split('@')[0].split('/')[1]

dns_libs_dir = os.path.join(work_dir, dns_libs_dir_name)
robust_clone(dns_libs_url, dns_libs_dir)
os.chdir(dns_libs_dir)
with open("conanfile.py", "r") as file:
    for line in map(str.strip, file.readlines()):
        if line.startswith('self.requires("native_libs_common/') \
                and ('@adguard/oss"' in line):
            nlc_versions.append(line.split('@')[0].split('/')[1])

subprocess.run([sys.executable, os.path.join("scripts", "export_conan.py"), dns_libs_version], check=True)
# Not leaving directory causes used-by-another-process error
os.chdir("..")
try:
    shutil.rmtree(dns_libs_dir, onerror=on_rm_tree_error)
except OSError:
    print(f"Warning: Could not remove {dns_libs_dir}, likely locked. Leaving it.")

os.chdir(work_dir)
nlc_dir = os.path.join(work_dir, nlc_dir_name)
robust_clone(nlc_url, nlc_dir)
os.chdir(nlc_dir)

# Reduce the chances of missing a necessary dependency exported with NLC
# by exporting all recipes from all versions of NLC, starting with the minimum
# necessary.
min_nlc_version = min(nlc_versions)
with open("conandata.yml", "r") as file:
    items = yaml.safe_load(file)["commit_hash"]

for v in nlc_versions: # [k for k in items.keys() if k >= min_nlc_version]:
    subprocess.run(["git", "checkout", "master"], check=True)
    try:
        subprocess.run([sys.executable, os.path.join(nlc_dir, "scripts", "export_conan.py"), v], check=True)
    except:
        if v in nlc_versions:
            raise
        else:
            # Some native_libs_common versions have broken Conan recipes: ignore them.
            continue

# Not leaving directory causes used-by-another-process error
os.chdir("..")
try:
    shutil.rmtree(nlc_dir, onerror=on_rm_tree_error)
except OSError:
    print(f"Warning: Could not remove {nlc_dir}, likely locked. Leaving it.")
