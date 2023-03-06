#!/usr/bin/env python3

import os
import subprocess
import sys

import yaml

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)
commit_hash_version = "777"

with open(os.path.join(project_dir, "conandata.yml"), "r") as file:
    yaml_data = yaml.safe_load(file)

versions = []
if len(sys.argv) == 1:
    versions.append(commit_hash_version)
    if len(yaml_data["commit_hash"]) > 0:
        versions.append(list(yaml_data["commit_hash"].keys())[-1])
elif sys.argv[1] == "all":
    versions.append(commit_hash_version)
    for version in yaml_data["commit_hash"]:
        versions.append(version)
else:
    versions.append(sys.argv[1])

branch_name = "master"
if "bamboo_repository_branch_name" in os.environ:
    branch_name = os.environ["bamboo_repository_branch_name"]

for version in versions:
    if False and version == commit_hash_version:
        subprocess.run(["git", "checkout", "-B", branch_name, "origin/" + branch_name], check=True)
    else:
        hash1 = yaml_data["commit_hash"][version]["hash"]
        the_hash = subprocess.run(["git", "log", "--reverse", "--ancestry-path", hash1 + ".." + branch_name, "--pretty=%h"],
                                  check=True, capture_output=True, text=True).stdout.splitlines()[0]
        print("HASH is ", the_hash)
        subprocess.run(["git", "checkout", the_hash], check=True)
    subprocess.run(["conan", "export", project_dir, "/" + version + "@AdguardTeam/NativeLibsCommon"],
                   check=True)
