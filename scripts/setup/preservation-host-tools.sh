#!/bin/sh
# Ubuntu/WSL host dependencies for storage-preservation C tests. No phone access.
set -eu
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev
