#!/bin/sh
# Fetch Vapor 4.122.2 and apply the patch, which adds
# HTTPServer.Configuration.makeBootstrap: Vapor otherwise builds NIOPosix's
# ServerBootstrap itself and takes no other group.
set -e
cd "$(dirname "$0")"
rm -rf .deps/vapor
mkdir -p .deps
git clone -q --depth 1 --branch 4.122.2 https://github.com/vapor/vapor.git .deps/vapor
git -C .deps/vapor apply ../../../vapor-make-bootstrap.patch
echo "Vapor patched in .deps/vapor"
