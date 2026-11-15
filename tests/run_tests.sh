#!/bin/sh
# Host tests for the portable core.  Run from the project root:  sh tests/run_tests.sh
set -e
BIN="${TMPDIR:-/tmp}/c3hole_test_core"
python3 tests/gen_fixtures.py
g++ -std=gnu++11 -O2 -Wall -Wextra -pthread tests/test_core.cpp src/core/dns.cpp -o "$BIN"
"$BIN"
