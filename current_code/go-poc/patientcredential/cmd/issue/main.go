package main

import (
	"crypto/rand"
	"log"
	"os"
	"path/filepath"
	"time"

	pc "github.com/nasif2005/healthcare-specific-idm/go-poc/patientcredential"
)

func main() {
	issuer, err := pc.NewIssuer("did:web:apc.example.org")
	if err != nil {
		log.Fatal(err)
	}
	secret, err := pc.NewRandomLinkSecret()
	if err != nil {
		log.Fatal(err)
	}
	commitment, err := pc.NewLinkSecretCommitment(secret)
	if err != nil {
		log.Fatal(err)
	}
	req := pc.PatientCredentialRequest{
		PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1",
		DateOfBirth: "1985-04-12", EligibilityStatus: "active",
		Jurisdiction: "CA-ON", LinkSecretCommitment: commitment,
	}
	now := time.Now().UTC()
	cred, err := issuer.Issue(req, "urn:uuid:hidm-demo-credential-1", now, now.AddDate(1, 0, 0))
	if err != nil {
		log.Fatal(err)
	}
	if err = issuer.Verify(cred, now); err != nil {
		log.Fatal(err)
	}
	artifactDir := "artifacts"
	if err = os.MkdirAll(artifactDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if err = pc.SavePatientCredential(filepath.Join(artifactDir, "patient_credential.json"), cred); err != nil {
		log.Fatal(err)
	}
	// Demonstration wallet key only. Do not hard-code or store this key in a
	// real deployment; obtain it from an OS wallet, KMS, or HSM.
	walletKey := make([]byte, 32)
	if _, err = rand.Read(walletKey); err != nil {
		log.Fatal(err)
	}
	if err = pc.SaveHolderSecret(filepath.Join(artifactDir, "patient_holder_secret.json"), cred.CredentialID, secret, walletKey); err != nil {
		log.Fatal(err)
	}
	pta, err := pc.NewPTAService(issuer, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	nonce, err := pta.NewChallenge(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	holder := &pc.Holder{Credential: cred, LinkSecret: secret}
	proof, err := holder.CreatePatientIDProofForNonce("demo-pta-session", nonce, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pseudonym, bindingProof, err := pc.NewPseudonym(cred.Subject.PatientID, cred.CredentialID, "hrr.example.org", "ehr-read-v1", nonce, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	token, err := pta.IssuePseudonymToken(cred, proof, nonce, "demo-pta-session", pc.PseudonymTokenRequest{Pseudonym: pseudonym, BindingProof: bindingProof, CredentialID: cred.CredentialID, Audience: "hrr.example.org", PolicyID: "ehr-read-v1", ExpiresAt: now.Add(24 * time.Hour)}, now, "urn:uuid:hidm-demo-token-1")
	if err != nil {
		log.Fatal(err)
	}
	if err = pc.SavePseudonymToken(filepath.Join(artifactDir, "pseudonym_token.json"), token); err != nil {
		log.Fatal(err)
	}

	// The APC verifies the credential presentation, then blindly signs the
	// patient-generated ATI. No provider identifier or ATI is sent to the APC.
	apc, err := pc.NewAppointmentTokenAuthority(issuer)
	if err != nil {
		log.Fatal(err)
	}
	appointmentNonce, err := apc.NewCredentialChallenge(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	appointmentProof, err := holder.CreatePatientIDProofForNonce("demo-apc-appointment-token", appointmentNonce, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	appointmentChallenge, err := apc.BeginIssuance(cred, appointmentProof, appointmentNonce, "demo-apc-appointment-token", now, now.Add(time.Hour), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ati, err := pc.NewAppointmentTokenID(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	blindRequest, blindingState, err := pc.PrepareBlindAppointmentToken(appointmentChallenge, ati)
	if err != nil {
		log.Fatal(err)
	}
	blindResponse, err := apc.SignBlindAppointmentToken(blindRequest)
	if err != nil {
		log.Fatal(err)
	}
	appointmentToken, err := pc.FinalizeAppointmentToken(appointmentChallenge, blindingState, blindResponse, apc.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	if err = pc.SaveAppointmentToken(filepath.Join(artifactDir, "appointment_token.json"), appointmentToken); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s, %s, %s, and %s", filepath.Join(artifactDir, "patient_credential.json"), filepath.Join(artifactDir, "patient_holder_secret.json"), filepath.Join(artifactDir, "pseudonym_token.json"), filepath.Join(artifactDir, "appointment_token.json"))
	log.Printf("demo wallet key is intentionally not written; preserve it only for this demonstration")
}
