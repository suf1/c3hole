#!/bin/sh
# Host tests for the portable core.  Run from the project root:  sh tests/run_tests.sh
set -e
BIN="${TMPDIR:-/tmp}/c3hole_test_core"
python3 tests/test_dashboard.py
if python3 -c "import serial" 2>/dev/null; then python3 tests/test_flasher.py; else echo "(flasher test skipped: pyserial not installed)"; fi
python3 tests/gen_fixtures.py
g++ -std=gnu++11 -O2 -Wall -Wextra -pthread tests/test_core.cpp src/core/dns.cpp -o "$BIN"
"$BIN"
