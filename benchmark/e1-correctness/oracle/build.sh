#!/usr/bin/env bash
# build.sh — build the kernel oracle runner, oracle/build/kernel_run.
#
# Needs only a C compiler and the system libbpf (headers + libbpf.so). Running
# the binary needs root (or CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON); building it
# does not. record.py is the only thing that runs it.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$HERE/build"
cc -O2 -Wall -Wextra -o "$HERE/build/kernel_run" "$HERE/kernel_run.c" -lbpf
"$HERE/build/kernel_run" --version
