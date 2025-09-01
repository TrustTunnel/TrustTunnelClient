#!/usr/bin/env python3

"""
This script exports the vpn-libs package to the local Conan cache.

By default, without any arguments, it exports the latest version from `conandata.yml`.

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

import yaml

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)

with open(os.path.join(project_dir, "conandata.yml"), "r") as file:
    yaml_data = yaml.safe_load(file)

versions = []
if len(sys.argv) == 1:
    if len(yaml_data["commit_hash"]) > 0:
        versions.append(list(yaml_data["commit_hash"].keys())[-1])
elif sys.argv[1] == "all":
    for version in yaml_data["commit_hash"]:
        versions.append(version)
elif sys.argv[1] == "local":
    result = subprocess.run(["git", "rev-parse", "--short","HEAD"], check=True, capture_output=True)
    last_commit_hash = result.stdout.decode().splitlines()[0]
    versions.append(last_commit_hash)

for version in versions:
    if re.match(r'\d+\.\d+\.\d+', version) is not None:
        hash1 = yaml_data["commit_hash"][version]["hash"]
        result = subprocess.run(["git", "log", "--reverse", "--ancestry-path", hash1 + "..master", "--pretty=%h"],
                                check=True, capture_output=True)
        the_hash = result.stdout.decode().splitlines()[0]
        print("HASH is ", the_hash)
        subprocess.run(["git", "checkout", the_hash], check=True)

    subprocess.run(["conan", "export", project_dir, "--user", "adguard", "--channel", "oss", "--version", version])
