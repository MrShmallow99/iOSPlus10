#!/bin/sh
# Host-only ARM64 disassembler for RAM-root startup failures.
set -eu
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends binutils-aarch64-linux-gnu
