#!/usr/bin/env bash
# Build with JDK 21. The system java and JAVA_HOME point at 1.8, so a plain "mvn" fails on
# release 21. Override the JDK with KMS_JAVA_HOME.
set -euo pipefail
JAVA21="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
if [[ -z "${JAVA21}" ]]; then
  echo "ERROR: JDK 21 not found. Install it or set KMS_JAVA_HOME." >&2
  exit 1
fi
export JAVA_HOME="${KMS_JAVA_HOME:-${JAVA21}}"
export PATH="${JAVA_HOME}/bin:${PATH}"
exec mvn "$@"
