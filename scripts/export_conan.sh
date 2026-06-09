#!/bin/sh

set -e

cd "$(dirname "$0")/.."

TAG=$(git tag -l 'v*' --sort=-v:refname | head -n1)
conan export . --user adguard --channel oss --version ${TAG#v}
