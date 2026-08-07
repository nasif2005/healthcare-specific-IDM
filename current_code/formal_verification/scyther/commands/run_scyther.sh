#!/usr/bin/env bash
set -euo pipefail

# Change this path if Scyther is installed elsewhere.
SCYTHER_BIN="${SCYTHER_BIN:-$HOME/scyther/src/scyther-linux}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

timeout 60 "$SCYTHER_BIN" --max-runs=2 "$ROOT/code/hidm_appointment_booking.spdl"
timeout 60 "$SCYTHER_BIN" --max-runs=2 "$ROOT/code/hidm_inperson_verification.spdl"

