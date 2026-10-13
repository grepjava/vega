#!/bin/sh
# Fetch Hummingbird at the commit the patch was made against and apply the
# patch, which adds ServerConfiguration.makeBootstrap: Hummingbird otherwise
# builds NIOPosix's ServerBootstrap itself and takes no other group.
set -e
cd "$(dirname "$0")"
rm -rf .deps/hummingbird
mkdir -p .deps
git clone -q https://github.com/hummingbird-project/hummingbird.git .deps/hummingbird
git -C .deps/hummingbird checkout -q 13c924d83c46031bc56fff27ce19c1be60eed74c
git -C .deps/hummingbird apply ../../../hummingbird-make-bootstrap.patch
echo "Hummingbird patched in .deps/hummingbird"
