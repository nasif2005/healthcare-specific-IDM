#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/results"
cd "$ROOT/code"

timeout 300 tamarin-prover --prove=no_link_without_audit_E6 HIDM_E6_privacy_1.spthy > "$ROOT/results/E6_no_link_without_audit.txt" 2>&1
timeout 300 tamarin-prover --prove=no_multi_verify_links_without_audit_E6 HIDM_E6_privacy_1.spthy > "$ROOT/results/E6_multi_verification_privacy.txt" 2>&1
timeout 300 tamarin-prover --prove=traceability_under_audit_possible_E6 HIDM_E6_privacy_1.spthy > "$ROOT/results/E6_traceability.txt" 2>&1

grep -H "verified" "$ROOT"/results/E6_*.txt

