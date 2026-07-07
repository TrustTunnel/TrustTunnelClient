#!/bin/sh

# Export vpn-libs (at the current `git describe` version) to the local Conan cache.
#
# The package is exported at the version reported by `git describe` (e.g.
# `1.1.5-beta.6` on a tag, or `1.1.5-beta.6-1-gb65d25d5` in between); when it is
# built, the recipe checks out the matching commit. To build uncommitted
# working-tree changes instead, use `conan create . --version local`.

set -e

cd "$(dirname "$0")/.."

version=$(git describe --tags --match "v*" | sed 's/^v//')
conan export . --user adguard --channel oss --version "$version"
