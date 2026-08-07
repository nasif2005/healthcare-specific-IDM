#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/results"
cd "$ROOT/code"

timeout 300 tamarin-prover --prove=no_link_without_audit HIDM_E5_privacy_1.spthy > "$ROOT/results/E5_no_link_without_audit.txt" 2>&1
timeout 300 tamarin-prover --prove=no_multi_booking_links_without_audit HIDM_E5_privacy_1.spthy > "$ROOT/results/E5_multi_booking_privacy.txt" 2>&1
timeout 300 tamarin-prover --prove=traceability_under_audit_possible HIDM_E5_privacy_1.spthy > "$ROOT/results/E5_traceability.txt" 2>&1

grep -H "verified" "$ROOT"/results/E5_*.txt

