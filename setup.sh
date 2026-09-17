#!/bin/sh
# setup.sh — create the virtualenv this artifact runs in, then check it.
#
#   ./setup.sh              venv/, dependencies, then a 250-check smoke test
#   ./setup.sh --no-check   set up only
#   PYTHON=python3.12 ./setup.sh
#
# Everything lands in venv/ next to this script; nothing outside the repository
# is touched, and re-running is safe.
set -eu

here=$(dirname "$(readlink -f "$0")")
cd "$here"
python=${PYTHON:-python3}
check=1
[ "${1:-}" = "--no-check" ] && check=0

if ! command -v "$python" >/dev/null 2>&1; then
    echo "setup.sh: no $python on PATH; set PYTHON=<interpreter>" >&2
    exit 1
fi
if ! "$python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    echo "setup.sh: Python 3.12 or newer is required, found $("$python" -V)" >&2
    exit 1
fi

if [ ! -x venv/bin/python ]; then
    echo "==> creating venv/ with $("$python" -V)"
    "$python" -m venv venv
fi

echo "==> installing requirements.txt"
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -r requirements.txt
venv/bin/python -c 'import z3, elftools, jsonschema, scapy'

if [ "$check" -eq 1 ]; then
    echo "==> checking the analyzer against the recorded kernel answers"
    venv/bin/python benchmark/e1-correctness/run.py cases | tail -n 1
fi

cat <<'EOF'

ready. From here:

  venv/bin/python -m hornet -i example/katran/balancer_main.o \
      -e balancer_ingress -c benchmark/specs/katran/balancer_main.json

  venv/bin/python benchmark/e1-correctness/run.py     # E1, all three suites
  venv/bin/python benchmark/e2-performance/run.py
  venv/bin/python benchmark/e3-casestudy/run.py
  venv/bin/python benchmark/e4-ablation/run.py

E1's `conformance` suite needs one more step, an external ISA test runner:
benchmark/e1-correctness/conformance/build.sh (network, cmake, a C++ compiler).
EOF
