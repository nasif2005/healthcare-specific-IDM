# HIDM BBS+ patient-credential issuance POC

This module implements the APC-side issuance, patient holder, PTA proof, and pseudonym-token paths for the HIDM proof of concept.

It uses `github.com/etclab/kryptology/pkg/signatures/bbs` v0.1.0 on BLS12-381. The credential is an application-specific JSON format; it is **not** claimed to be interoperable with W3C VC/BBS+ presentations yet.

## Run

```powershell
go test ./...
go run ./cmd/issue
go run ./cmd/measure-issuance -iterations 30 -output patient_credential_issuance_measurements.json
go run ./cmd/measure-pseudonym-token-issuance -iterations 30 -output pseudonym_token_issuance_measurements.json
go run ./cmd/measure-appointment-token-issuance -iterations 30 -output appointment_token_issuance_measurements.json
```

## Patient credential issuance measurements

`cmd/measure-issuance` measures the complete credential-issuance workflow over
the requested number of repetitions. It reports end-to-end latency in
milliseconds (min, mean, median, p95, max), compact JSON request and response
sizes, and the byte sizes of the patient-held credential and encrypted holder
secret. Issuer key generation and filesystem I/O are excluded from latency;
network transport headers/TLS and backend replication are excluded from size
figures. The command writes JSON suitable for the experimental-results tables.

`cmd/measure-pseudonym-token-issuance` measures PTA challenge generation,
selective-disclosure proof and pseudonym/PBP generation, token issuance, and
token verification. Its communication measurement includes the POC's full
credential, selective-disclosure proof, and token-request JSON sent to the PTA;
the response is the issued pseudonym token. Persistent storage is the
patient-held pseudonym-token JSON. As above, transport overhead, issuer setup,
PTA signing-key setup, and filesystem I/O are excluded from latency.

`cmd/measure-appointment-token-issuance` measures the credential challenge,
selective-disclosure presentation, blind-signature challenge, blind request,
blind response, token finalization, and token verification. It reports each of
the four serialized protocol-message sizes and aggregates the two directions
of communication. The appointment token is finalized locally and its
patient-held JSON size is reported as persistent storage.

The demo writes generated artifacts to `artifacts/` in the module directory:

```text
artifacts/patient_credential.json
artifacts/patient_holder_secret.json
artifacts/pseudonym_token.json
artifacts/appointment_token.json
```

The demo wallet key is generated in memory and intentionally not written. Without that key, the encrypted holder-secret JSON cannot be opened; a real wallet would obtain the key from secure storage.

The test suite covers valid issuance, claim tampering, expiry, and deterministic link-secret commitments.

## Workflow implemented

1. The patient creates a 32-byte link secret locally.
2. The patient sends APC a commitment to that secret together with the authenticated PatientID and claims.
3. APC signs a fixed, domain-separated, ordered BBS+ message vector.
4. APC returns a credential containing the signature, public key, schema, expiry, and message order.
5. Verification reconstructs the same scalar vector and verifies the BBS+ signature.

The raw link secret is never placed in the credential. The Cha--Cheon extraction workflow is a separate module; when it produces a pseudonym-specific private key, store it with `SavePseudonymPrivateKey` in the encrypted `pseudonym_private_key.json` file.

## Storage files

Use `SavePatientCredential` and `LoadPatientCredential` for `patient_credential.json`. Use `SaveHolderSecret` and `LoadHolderSecret` for `patient_holder_secret.json`; the raw link secret is encrypted with AES-256-GCM under a caller-provided wallet key. Use `SavePseudonymToken` and `LoadPseudonymToken` for `pseudonym_token.json`. Use `SaveAppointmentToken` and `LoadAppointmentToken` for `appointment_token.json`; it contains the patient-held ATI and its blinded signature, but no PatientID, pseudonym, or provider identifier. Use `SavePseudonymPrivateKey` and `LoadPseudonymPrivateKey` for `pseudonym_private_key.json`; it encrypts raw Cha--Cheon private group-element bytes and authenticates their key metadata. The wallet key itself must come from secure OS/KMS/HSM storage and must not be written beside the JSON files.

## Separated APC, patient, and PTA workflow

APC uses `Issuer.Issue` for the Patient â†’ APC issuance step. The patient stores the returned credential and raw link secret in a `Holder`. PTA uses `PTA.NewChallenge` to create a fresh 32-byte challenge, the patient calls `Holder.CreatePatientIDProofForNonce`, and PTA calls `PTA.VerifyPatientIDProof`. The resulting BBS+ proof reveals only `patient_id`; all other signed attributes remain hidden.

The PTA verifier tracks used `(credential_id, nonce)` pairs in this proof of concept, so a proof cannot be accepted twice. In a multi-process deployment this replay state must be backed by a shared transactional store.

## Pseudonym-token issuance

After receiving the PTA challenge, the patient creates a BLS12-381 pairing-based PRE pseudonym with `NewPseudonym`. It serializes the pseudonym components \((P_1,P_2)\), the pseudonym-generation public key, and a Fiat--Shamir Pseudonym Binding Proof (PBP). `PTAService.IssuePseudonymToken` verifies the BBS+ credential presentation, then verifies the PBP against the selectively disclosed `patient_id`, credential identifier, audience, policy, and one-time PTA nonce before signing the token using ordinary Kyber Schnorr. The token does not contain `patient_id`; the PTA retains the pseudonym-to-patient mapping in its trace store. A provider verifies the token with `VerifyPseudonymToken` and checks its audience and expiry.

`TracePseudonym` is only a proof-of-concept hook. Production conditional tracing requires threshold authorization, audit logging, and protected shared storage.

## Appointment-token issuance

`AppointmentTokenAuthority` implements the APC side of provider-agnostic partially blind Schnorr issuance. The APC first verifies the patient's selective BBS+ `patient_id` presentation. The patient then generates the UUIDv4 ATI locally and calls `PrepareBlindAppointmentToken`; the APC receives only a blinded challenge, never the ATI or a future provider identifier. `FinalizeAppointmentToken` produces an `AppointmentToken` containing the ATI, public expiry information, and an APC-verifiable signature. A healthcare provider calls `VerifyAppointmentToken` and then atomically calls `AppointmentTokenUsageLedger.Consume` to enforce one-time use. The in-memory ledger is only a POC; deployment requires a durable, transactional provider-side spent-token registry. It must not be shared with the APC if the no-linking requirement is to be preserved.

## Appointment booking

`AppointmentBookingService` verifies a signed `AppointmentScheduleRequest`, verifies and atomically consumes the Appointment Token, and creates an `AppointmentBookingRecord` containing a confirmation code and a hashed ATI-use reference. Store the patient-held request with `SaveAppointmentScheduleRequest` in `appointment_schedule_request.json` and the healthcare-organization record with `SaveAppointmentBookingRecord` in `appointment_booking_record.json`. The provider record does not retain the raw ATI.

The booking service intentionally requires a `PseudonymIBSVerifier` interface. Connect a real Cha--Cheon IBS verifier to this interface after the pseudonym-specific private-key extraction and IBS signing modules are implemented. The current repository does not label a different signature algorithm as Cha--Cheon IBS; the test suite uses a test-only verifier solely to exercise the workflow boundary.

## In-person identity verification

`InPersonIdentityVerificationService` validates an active booking, one-time session nonce, pseudonym-specific IBS signature, PTA-issued Pseudonym Token, policy-scoped credential presentation, and an in-memory biometric comparison result. It stores the patient-held request through `SaveInPersonIdentityVerificationRequest` in `identity_verification_request.json` and the minimal provider record through `SaveIdentityVerificationRecord` in `identity_verification_record.json`. The provider record contains a protected appointment reference, pseudonym, outcome, and timestamp; it excludes raw biometrics, credential presentation, and raw confirmation code.

The POC requires `CredentialPresentationVerifier` and `BiometricComparisonVerifier` interfaces. A production system must connect these to an appropriate BBS+ selective-disclosure verifier and a governed biometric subsystem that processes and erases biometric material in volatile memory.

The holder's raw link secret is checked locally against the signed commitment and is never sent to the PTA. This POC demonstrates knowledge of the BBS+ signed messages and selective disclosure; a separate hash-preimage proof would be needed if the paper claims a formal proof of knowledge of the raw link-secret preimage itself.
