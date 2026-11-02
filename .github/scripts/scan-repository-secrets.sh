#!/usr/bin/env bash
# Scan the current repository tree with its own automatically discovered config.
set -euo pipefail

if [[ $# -gt 1 ]]; then
  printf '%s\n' 'usage: scan-repository-secrets.sh [repository-directory]' >&2
  exit 2
fi
if [[ ${GITLEAKS_BIN:-} != /* || ! -x ${GITLEAKS_BIN:-} ]]; then
  printf '%s\n' 'GITLEAKS_BIN must name an absolute executable path to verified Gitleaks 8.30.1.' >&2
  exit 2
fi
if [[ $("$GITLEAKS_BIN" version) != 8.30.1 ]]; then
  printf '%s\n' 'The repository scanner requires Gitleaks 8.30.1.' >&2
  exit 2
fi
if [[ -n ${GITLEAKS_REPORT_PATH:-} && $GITLEAKS_REPORT_PATH != /* ]]; then
  printf '%s\n' 'GITLEAKS_REPORT_PATH must be an absolute path when set.' >&2
  exit 2
fi

repository=$(cd -- "${1:-.}" && pwd -P)
arguments=(dir . --redact=100 --no-banner --no-color --max-target-megabytes 0)
if [[ -n ${GITLEAKS_REPORT_PATH:-} ]]; then
  arguments+=(--report-format json --report-path "$GITLEAKS_REPORT_PATH")
fi
# A caller's scanner config must not replace this repository's reviewed config.
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
cd -- "$repository"
"$GITLEAKS_BIN" "${arguments[@]}"
