#!/usr/bin/env python3

"""
This script intended to collect all the changes between the specific versions.

Usage:
    extract_changelog.py [v]X [[v]Y]

`X` is the oldest version number from which the records start (the changes
from `X` itself are not included).
`Y` is the latest version number on which the records end (the changes
from `Y` itself are not included).
In case `Y` is omitted, the script collects all the records until the latest version.
`v` before the version number is optional, that is, `v1.1.1` is the same as `1.1.1`.
"""

import sys


def parse_version(s: str):
    return tuple(map(int, s.split('.')))


oldest_version = parse_version(sys.argv[1].removeprefix('v'))
latest_version = parse_version(sys.argv[2].removeprefix('v')) if len(sys.argv) > 2 else None

with open('CHANGELOG.md', 'r', encoding='UTF-8') as file:
    recording = False
    output = ''
    lines = file.readlines()

    for line in map(str.rstrip, lines):
        if line.startswith('## '):
            found_version = parse_version(line.removeprefix('## '))
            if latest_version is None:
                found_version = latest_version
            if oldest_version < found_version <= latest_version:
                recording = True
            else:
                break
        elif recording and len(line) > 0:
            output += line + '\n'

    print(output)
