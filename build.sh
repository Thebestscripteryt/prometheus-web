#!/usr/bin/env bash
set -euo pipefail

npm install

BIN_PATH="$PWD/vendor/bin/lua5.1"

if [ ! -f "$BIN_PATH" ]; then
  echo "Building lua5.1 from source..."
  mkdir -p vendor
  curl -sSR -o vendor/lua-5.1.5.tar.gz https://www.lua.org/ftp/lua-5.1.5.tar.gz
  tar -xzf vendor/lua-5.1.5.tar.gz -C vendor
  make -C vendor/lua-5.1.5 linux MYCFLAGS="-fPIC"
  mkdir -p vendor/bin
  cp vendor/lua-5.1.5/src/lua vendor/bin/lua5.1
  rm -rf vendor/lua-5.1.5 vendor/lua-5.1.5.tar.gz
  echo "lua5.1 built at $BIN_PATH"
else
  echo "lua5.1 already built, skipping."
fi
