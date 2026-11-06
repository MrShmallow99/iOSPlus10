#!/bin/sh
# Host-only emulator; no phone access, USB passthrough, or network service setup.
set -eu
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-system-arm
