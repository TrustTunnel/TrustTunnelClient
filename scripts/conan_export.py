#!/usr/bin/env python3

"""
This script exports the vpn-libs package to the local Conan cache.

By default, without any arguments, it exports the latest version from git tags.

Pass `all` as an argument to export all versions (e.g., `conan_export.py all`).

Pass a version number as an argument to export only that specific version
(e.g., `conan_export.py 1.0.0`).

Pass 'local' as an argument to export current version of libs with hash of the last commit as version.
(e.g., `conan_export.py local`).
"""

import os
import subprocess
import sys
import re

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)


def get_all_versions():
    """Get all version tags from git."""
    result = subprocess.run(
        ["git", "tag", "-l", "v*"],
        check=True,
        capture_output=True,
        cwd=project_dir
    )
    tags = result.stdout.decode().strip().split('\n')
    # Filter and extract version numbers from tags like 'v1.0.0'
    versions = []
    for tag in tags:
        if tag and re.match(r'^v\d+\.\d+\.\d+$', tag):
            versions.append(tag[1:])  # Remove 'v' prefix
    return sorted(versions, key=lambda v: [int(x) for x in v.split('.')])


def get_latest_version():
    """Get the latest version tag from git."""
    versions = get_all_versions()
    return versions[-1] if versions else None


versions = []
if len(sys.argv) == 1:
    latest = get_latest_version()
    if latest:
        versions.append(latest)
    else:
        print("No version tags found")
        sys.exit(1)
elif sys.argv[1] == "all":
    versions = get_all_versions()
elif sys.argv[1] == "local":
    result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], check=True, capture_output=True)
    last_commit_hash = result.stdout.decode().splitlines()[0]
    versions.append(last_commit_hash)
else:
    versions.append(sys.argv[1])

for version in versions:
    if re.match(r'\d+\.\d+\.\d+', version) is not None:
        # Checkout the tag for the version
        subprocess.run(["git", "checkout", f"v{version}"], check=True, cwd=project_dir)

    subprocess.run(["conan", "export", project_dir, "--user", "adguard", "--channel", "oss", "--version", version])
