#!/usr/bin/env bash
# Full verification: Java unit tests plus cross-implementation conformance. Both must pass.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> [1/2] Java unit tests"
./build.sh -q test

echo "==> [2/2] Cross-implementation conformance (independent Node/OpenSSL implementation)"
node tools/envelope_check.mjs

echo "==> all green"
