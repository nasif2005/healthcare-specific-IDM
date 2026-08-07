# Formal verification â€” current HIDM implementation

This directory collects the formal-analysis artifacts associated with the
current HIDM proof of concept. Source models, execution commands, and saved
output are separated so that the results can be reproduced without confusing
them with the earlier implementation.

```text
formal_verification/
â”œâ”€â”€ scyther/
â”‚   â”œâ”€â”€ code/       # E5 and E6 symbolic protocol models (.spdl)
â”‚   â”œâ”€â”€ commands/   # Linux execution command
â”‚   â””â”€â”€ results/    # Place Scyther console output here after a run
â””â”€â”€ tamarin/
    â”œâ”€â”€ code/       # E5 and E6 privacy models (.spthy)
    â”œâ”€â”€ commands/   # Reproducible Linux proof commands
    â””â”€â”€ results/    # Six saved, targeted-proof outputs
```

## Scope

The Scyther models cover the E5 appointment-booking and E6 in-person
verification message flows. They abstract token issuance as a valid
pre-existing input; expiry and one-time token use remain implementation-side
state checks.

The Tamarin models analyze pre-audit unlinkability and audit-enabled
traceability for E5 and E6. The saved outputs verify all six targeted lemmas.
They were generated with Tamarin 1.11.0. The output reports Maude 2.7 as
unsupported, so final publication results should be rerun with a supported
Maude version.

