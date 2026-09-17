#!/bin/sh
# Build bpf_conformance_runner for E1's `conformance` suite.
#
# Only the runner: its libbpf plugin (the kernel reference) needs BPF
# privileges, and the tests already carry the kernel-agreed r0, so it is not
# needed to judge hornet.
#
# The upstream commit is pinned: the suite grows over time, and conformance/
# baseline.json records the status of the 313 tests this one has. Cloning and
# fetching the one submodule the runner needs the network.
set -eu
rev=5ec6ba9e02fcecb568e617855578710d1fedad87
here=$(dirname "$(readlink -f "$0")")
src="$here/../bpf_conformance"

if [ ! -d "$src/.git" ]; then
    git clone https://github.com/Alan-Jowett/bpf_conformance.git "$src"
fi
git -C "$src" checkout --quiet "$rev"
git -C "$src" submodule update --init external/elfio
cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$src/build" --target bpf_conformance_runner -j "$(nproc)"
echo "runner: $src/build/bin/bpf_conformance_runner"
