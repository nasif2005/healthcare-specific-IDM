package patientcredential

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCredential(t *testing.T) (*Issuer, *Credential, time.Time, []byte) {
	t.Helper()
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewRandomLinkSecret()
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := NewLinkSecretCommitment(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	cred, err := issuer.Issue(PatientCredentialRequest{
		PatientID: "APC-00012345", PatientReference: "opaque-ref-1",
		DateOfBirth: "1985-04-12", EligibilityStatus: "active",
		Jurisdiction: "CA-ON", LinkSecretCommitment: commitment,
	}, "urn:uuid:test-credential", now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return issuer, cred, now, secret
}

func TestIssueAndVerify(t *testing.T) {
	issuer, cred, now, _ := testCredential(t)
	if err := issuer.Verify(cred, now); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedClaimFails(t *testing.T) {
	issuer, cred, now, _ := testCredential(t)
	cred.Subject.EligibilityStatus = "revoked"
	if err := issuer.Verify(cred, now); err == nil {
		t.Fatal("tampered claim was accepted")
	}
}

func TestExpiredCredentialFails(t *testing.T) {
	issuer, cred, now, _ := testCredential(t)
	if err := issuer.Verify(cred, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired credential was accepted")
	}
}

func TestLinkSecretCommitmentIsDeterministic(t *testing.T) {
	secret := []byte("test-link-secret")
	a, err := NewLinkSecretCommitment(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewLinkSecretCommitment(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualCommitment(a, b) {
		t.Fatal("same secret produced different commitments")
	}
}

func TestPatientIDSelectiveDisclosure(t *testing.T) {
	issuer, cred, now, secret := testCredential(t)
	holder := &Holder{Credential: cred, LinkSecret: secret}
	pta := NewPTA(issuer)
	nonce, err := pta.NewChallenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := holder.CreatePatientIDProofForNonce("pta-session-1", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revealed, err := pta.VerifyPatientIDProof(cred, proof, "pta-session-1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if revealed != cred.Subject.PatientID {
		t.Fatalf("revealed %q, want %q", revealed, cred.Subject.PatientID)
	}
	if _, err = pta.VerifyPatientIDProof(cred, proof, "pta-session-1", nonce); err == nil {
		t.Fatal("proof challenge was accepted twice")
	}
	_ = now
}

func TestPseudonymTokenIssuanceAndVerification(t *testing.T) {
	issuer, cred, now, secret := testCredential(t)
	pta, err := NewPTAService(issuer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := pta.NewChallenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder := &Holder{Credential: cred, LinkSecret: secret}
	proof, err := holder.CreatePatientIDProofForNonce("pta-token-session", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pseudonym, bindingProof, err := NewPseudonym(cred.Subject.PatientID, cred.CredentialID, "hrr.example.org", "ehr-read-v1", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pta.IssuePseudonymToken(cred, proof, nonce, "pta-token-session", PseudonymTokenRequest{
		Pseudonym: pseudonym, BindingProof: bindingProof, CredentialID: cred.CredentialID, Audience: "hrr.example.org",
		PolicyID: "ehr-read-v1", ExpiresAt: now.Add(time.Hour),
	}, now, "urn:uuid:test-token")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPseudonymToken(token, now, "hrr.example.org"); err != nil {
		t.Fatal(err)
	}
	if token.Pseudonym == cred.Subject.PatientID {
		t.Fatal("token exposed patient identity")
	}
	if _, ok := pta.TracePseudonym(token.Pseudonym); !ok {
		t.Fatal("trace mapping was not recorded")
	}
	token.Audience = "attacker.example.org"
	if err = VerifyPseudonymToken(token, now, "hrr.example.org"); err == nil {
		t.Fatal("tampered token was accepted")
	}
}

func TestPairingPseudonymBindingRejectsWrongTranscript(t *testing.T) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	pseudonym, bindingProof, err := NewPseudonym("APC-00012345", "urn:uuid:credential-1", "hrr.example.org", "ehr-read-v1", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPseudonymBinding(pseudonym, bindingProof, "APC-00012345", "urn:uuid:credential-1", "hrr.example.org", "ehr-read-v1", nonce); err != nil {
		t.Fatalf("valid PBP rejected: %v", err)
	}
	if err = VerifyPseudonymBinding(pseudonym, bindingProof, "APC-99999999", "urn:uuid:credential-1", "hrr.example.org", "ehr-read-v1", nonce); err == nil {
		t.Fatal("PBP accepted an unrelated patient ID")
	}
	if err = VerifyPseudonymBinding(pseudonym, bindingProof, "APC-00012345", "urn:uuid:credential-1", "other.example.org", "ehr-read-v1", nonce); err == nil {
		t.Fatal("PBP accepted a changed audience")
	}
}

func TestCredentialAndHolderSecretJSONStorage(t *testing.T) {
	issuer, cred, _, _ := testCredential(t)
	secret := []byte("holder-secret-for-storage")
	walletKey := []byte("01234567890123456789012345678901")
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "patient_credential.json")
	secretPath := filepath.Join(dir, "patient_holder_secret.json")
	if err := SavePatientCredential(credentialPath, cred); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPatientCredential(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = issuer.Verify(loaded, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err = SaveHolderSecret(secretPath, cred.CredentialID, secret, walletKey); err != nil {
		t.Fatal(err)
	}
	loadedSecret, err := LoadHolderSecret(secretPath, cred.CredentialID, walletKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(loadedSecret) != string(secret) {
		t.Fatal("holder secret round trip failed")
	}
	raw, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == string(secret) {
		t.Fatal("holder secret was stored as plaintext")
	}
}

func TestPseudonymPrivateKeyJSONStorage(t *testing.T) {
	walletKey := make([]byte, 32)
	if _, err := rand.Read(walletKey); err != nil {
		t.Fatal(err)
	}
	privateKey := []byte("serialized-cha-cheon-g1-private-key-point")
	path := filepath.Join(t.TempDir(), "pseudonym_private_key.json")
	key := &PseudonymPrivateKey{
		KeyID: "key-demo-1", PseudonymID: "pyn_demo", APCVerificationMethod: "did:web:apc.example.org#ibs-key-1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339), PrivateKey: privateKey,
	}
	if err := SavePseudonymPrivateKey(path, key, walletKey); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) == string(privateKey) || bytes.Contains(stored, privateKey) {
		t.Fatal("private key was written in plaintext")
	}
	loaded, err := LoadPseudonymPrivateKey(path, walletKey)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyID != key.KeyID || loaded.PseudonymID != key.PseudonymID || !bytes.Equal(loaded.PrivateKey, privateKey) {
		t.Fatal("pseudonym private key did not round-trip")
	}
	var envelope PseudonymPrivateKeyEnvelope
	if err = json.Unmarshal(stored, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.PseudonymID = "pyn_tampered"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPseudonymPrivateKey(path, walletKey); err == nil {
		t.Fatal("tampered pseudonym metadata was accepted")
	}
}

func issueTestAppointmentToken(t *testing.T) (*AppointmentToken, *AppointmentTokenAuthority, time.Time) {
	t.Helper()
	issuer, credential, now, secret := testCredential(t)
	authority, err := NewAppointmentTokenAuthority(issuer)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := authority.NewCredentialChallenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder := &Holder{Credential: credential, LinkSecret: secret}
	proof, err := holder.CreatePatientIDProofForNonce("appointment-token-session", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := authority.BeginIssuance(credential, proof, nonce, "appointment-token-session", now, now.Add(time.Hour), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ati, err := NewAppointmentTokenID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := PrepareBlindAppointmentToken(challenge, ati)
	if err != nil {
		t.Fatal(err)
	}
	response, err := authority.SignBlindAppointmentToken(request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := FinalizeAppointmentToken(challenge, state, response, authority.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return token, authority, now
}

func TestAppointmentTokenBlindIssuanceAndOneTimeUse(t *testing.T) {
	token, _, now := issueTestAppointmentToken(t)
	if err := VerifyAppointmentToken(token, now); err != nil {
		t.Fatalf("valid appointment token rejected: %v", err)
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("APC-00012345")) || bytes.Contains(encoded, []byte("opaque-ref-1")) {
		t.Fatal("appointment token exposed patient information")
	}
	ledger := NewAppointmentTokenUsageLedger()
	if err = ledger.Consume(token, now); err != nil {
		t.Fatal(err)
	}
	if err = ledger.Consume(token, now); err == nil {
		t.Fatal("appointment token was accepted twice")
	}
	token.ATI = "tampered-ati"
	if err = VerifyAppointmentToken(token, now); err == nil {
		t.Fatal("tampered appointment token was accepted")
	}
}

func TestAppointmentTokenJSONStorage(t *testing.T) {
	token, _, now := issueTestAppointmentToken(t)
	path := filepath.Join(t.TempDir(), "appointment_token.json")
	if err := SaveAppointmentToken(path, token); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAppointmentToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ATI != token.ATI || loaded.SignatureS != token.SignatureS {
		t.Fatal("appointment token did not round-trip")
	}
	if err = VerifyAppointmentToken(loaded, now); err != nil {
		t.Fatal(err)
	}
}

type testPseudonymIBSVerifier struct{}

func (testPseudonymIBSVerifier) VerifyPseudonymSignature(pseudonym string, message []byte, signature string) error {
	if pseudonym == "" || len(message) == 0 || signature != "test-cha-cheon-ibs-signature" {
		return errors.New("invalid test pseudonym signature")
	}
	return nil
}

func TestAppointmentBookingConsumesTokenAndStoresJSON(t *testing.T) {
	token, _, now := issueTestAppointmentToken(t)
	ledger := NewAppointmentTokenUsageLedger()
	booking, err := NewAppointmentBookingService("did:web:clinic.example.org", testPseudonymIBSVerifier{}, ledger)
	if err != nil {
		t.Fatal(err)
	}
	request := &AppointmentScheduleRequest{
		Type:                      AppointmentScheduleRequestType,
		PAI:                       PseudonymAccessInformation{Pseudonym: "pyn_visit_scoped", ReEncryptionKey: "rk_demo", PatientIDCiphertext: "ct_demo"},
		AppointmentToken:          token,
		ScheduleInfo:              AppointmentScheduleInfo{Date: "2026-08-01", TimeSlot: "10:30", Service: "primary-care"},
		HealthcareOrganizationDID: "did:web:clinic.example.org", SessionNonce: "session-nonce-demo",
		PseudonymSignature: "test-cha-cheon-ibs-signature",
	}
	record, err := booking.Book(request, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if record.AppointmentConfirmationCode == "" || record.TokenUseReference == "" {
		t.Fatal("booking record is incomplete")
	}
	if record.TokenUseReference == token.ATI {
		t.Fatal("booking record retained the raw ATI")
	}
	if _, err = booking.Book(request, now, rand.Reader); err == nil {
		t.Fatal("spent appointment token was accepted for a second booking")
	}
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "appointment_schedule_request.json")
	recordPath := filepath.Join(dir, "appointment_booking_record.json")
	if err = SaveAppointmentScheduleRequest(requestPath, request); err != nil {
		t.Fatal(err)
	}
	if err = SaveAppointmentBookingRecord(recordPath, record); err != nil {
		t.Fatal(err)
	}
	loadedRequest, err := LoadAppointmentScheduleRequest(requestPath)
	if err != nil || loadedRequest.AppointmentToken.ATI != token.ATI {
		t.Fatal("appointment scheduling request did not round-trip")
	}
	loadedRecord, err := LoadAppointmentBookingRecord(recordPath)
	if err != nil || loadedRecord.AppointmentConfirmationCode != record.AppointmentConfirmationCode {
		t.Fatal("appointment booking record did not round-trip")
	}
}

type testCredentialPresentationVerifier struct{}

func (testCredentialPresentationVerifier) VerifyCredentialPresentation(presentation []byte, policyID string) error {
	if policyID != "visit-identity-v1" || string(presentation) != `{"proof":"valid"}` {
		return errors.New("invalid test credential presentation")
	}
	return nil
}

type testBiometricComparisonVerifier struct{}

func (testBiometricComparisonVerifier) VerifyBiometricComparison(value string) (bool, error) {
	return value == "session-biometric-comparison-value", nil
}

func issueTestPseudonymTokenForAudience(t *testing.T, audience, policy string) (*PseudonymToken, time.Time) {
	t.Helper()
	issuer, credential, now, secret := testCredential(t)
	pta, err := NewPTAService(issuer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := pta.NewChallenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder := &Holder{Credential: credential, LinkSecret: secret}
	proof, err := holder.CreatePatientIDProofForNonce("in-person-identity-session", nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pseudonym, bindingProof, err := NewPseudonym(credential.Subject.PatientID, credential.CredentialID, audience, policy, nonce, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pta.IssuePseudonymToken(credential, proof, nonce, "in-person-identity-session", PseudonymTokenRequest{
		Pseudonym: pseudonym, BindingProof: bindingProof, CredentialID: credential.CredentialID,
		Audience: audience, PolicyID: policy, ExpiresAt: now.Add(time.Hour),
	}, now, "urn:uuid:in-person-pt")
	if err != nil {
		t.Fatal(err)
	}
	return token, now
}

func TestInPersonIdentityVerificationAndJSONStorage(t *testing.T) {
	const organizationDID = "did:web:clinic.example.org"
	const policyID = "visit-identity-v1"
	appointmentToken, _, now := issueTestAppointmentToken(t)
	pseudonymToken, _ := issueTestPseudonymTokenForAudience(t, organizationDID, policyID)
	bookingService, err := NewAppointmentBookingService(organizationDID, testPseudonymIBSVerifier{}, NewAppointmentTokenUsageLedger())
	if err != nil {
		t.Fatal(err)
	}
	bookingRecord, err := bookingService.Book(&AppointmentScheduleRequest{
		Type:                      AppointmentScheduleRequestType,
		PAI:                       PseudonymAccessInformation{Pseudonym: pseudonymToken.Pseudonym, ReEncryptionKey: "rk_demo", PatientIDCiphertext: "ct_demo"},
		AppointmentToken:          appointmentToken,
		ScheduleInfo:              AppointmentScheduleInfo{Date: "2026-08-01", TimeSlot: "11:00", Service: "primary-care"},
		HealthcareOrganizationDID: organizationDID, SessionNonce: "booking-session", PseudonymSignature: "test-cha-cheon-ibs-signature",
	}, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewInPersonIdentityVerificationService(organizationDID, policyID, testPseudonymIBSVerifier{}, testCredentialPresentationVerifier{}, testBiometricComparisonVerifier{}, bookingService)
	if err != nil {
		t.Fatal(err)
	}
	request := &InPersonIdentityVerificationRequest{
		Type: IdentityVerificationRequestType, AppointmentConfirmationCode: bookingRecord.AppointmentConfirmationCode,
		BiometricComparisonValue: "session-biometric-comparison-value", CredentialPresentation: json.RawMessage(`{"proof":"valid"}`),
		PseudonymToken: pseudonymToken, HealthcareOrganizationDID: organizationDID,
		SessionNonce: "identity-session", PseudonymSignature: "test-cha-cheon-ibs-signature",
	}
	record, err := service.Verify(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != "verified" || record.ProtectedAppointmentReference == bookingRecord.AppointmentConfirmationCode {
		t.Fatal("identity verification record is invalid")
	}
	if _, err = service.Verify(request, now); err == nil {
		t.Fatal("identity verification session was accepted twice")
	}
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "identity_verification_request.json")
	recordPath := filepath.Join(dir, "identity_verification_record.json")
	if err = SaveInPersonIdentityVerificationRequest(requestPath, request); err != nil {
		t.Fatal(err)
	}
	if err = SaveIdentityVerificationRecord(recordPath, record); err != nil {
		t.Fatal(err)
	}
	loadedRequest, err := LoadInPersonIdentityVerificationRequest(requestPath)
	if err != nil || loadedRequest.SessionNonce != request.SessionNonce {
		t.Fatal("identity verification request did not round-trip")
	}
	loadedRecord, err := LoadIdentityVerificationRecord(recordPath)
	if err != nil || loadedRecord.ProtectedAppointmentReference != record.ProtectedAppointmentReference {
		t.Fatal("identity verification record did not round-trip")
	}
}
