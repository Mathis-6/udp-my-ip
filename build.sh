#!/bin/bash
set -euo pipefail

args="${*:1}"

$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER -o /tmp/udp-my-ip -O3 server.c $args

