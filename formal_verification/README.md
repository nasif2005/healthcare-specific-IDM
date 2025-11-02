formal_verification/README.md   

# Formal Verification — Healthcare-Specific IDM Framework

This directory contains the formal verification artifacts for the paper  
**“Privacy-Preserving Patient Identity Management Framework for Secure Healthcare Access”**  
(*IEEE Access, 2025*).

The models validate the HIDM framework’s **security** and **privacy** guarantees using two complementary tools:

- **Scyther** — symbolic verification of message-level properties such as confidentiality, synchronization, and integrity.  
- **Tamarin Prover** — trace-based analysis of privacy properties, including pseudonymous authentication, unlinkability, and conditional traceability.

All models correspond to **Episodes 5 (Appointment Booking)** and **Episode 6 (In-Person Verification)** of the HIDM workflow.  
They confirm resilience to eavesdropping, replay, impersonation, and linkability attacks under the Dolev–Yao model.

---

## ⚙️ Installation

To reproduce the formal verification results, install the following dependencies:

### 1. Scyther
```bash
sudo apt-get update
sudo apt-get install scyther
# or build manually:
# git clone https://github.com/cascremers/scyther.git
# cd scyther && make


sudo apt-get update
sudo apt-get install tamarin-prover maude graphviz
# Verify correct Maude version (must be ≥ 3.2.1)
maude --version

