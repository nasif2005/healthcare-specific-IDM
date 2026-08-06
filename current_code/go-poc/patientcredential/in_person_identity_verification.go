package patientcredential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	IdentityVerificationRequestType = "HIDMIdentityVerificationRequest-v1"
	IdentityVerificationRecordType  = "HIDMIdentityVerificationRecord-v1"
)

// InPersonIdentityVerificationRequest is the patient-held request. The
// credential presentation is opaque because a complete zero-disclosure BBS+
// proof verifier is an integration boundary in this POC.
type InPersonIdentityVerificationRequest struct {
	Type                        string          `json:"type"`
	AppointmentConfirmationCode string          `json:"appointment_confirmation_code"`
	BiometricComparisonValue    string          `json:"biometric_comparison_value"`
	CredentialPresentation      json.RawMessage `json:"credential_presentation"`
	PseudonymToken              *PseudonymToken `json:"pseudonym_token"`
	HealthcareOrganizationDID   string          `json:"healthcare_organization_did"`
	SessionNonce                string          `json:"session_nonce"`
	PseudonymSignature          string          `json:"pseudonym_signature"`
}

// IdentityVerificationRecord is the minimal provider-side audit record. It
// excludes raw biometrics, the credential presentation, and the raw booking
// confirmation code.
type IdentityVerificationRecord struct {
	Type                          string `json:"type"`
	ProtectedAppointmentReference string `json:"protected_appointment_reference"`
	Pseudonym                     string `json:"pseudonym"`
	Outcome                       string `json:"outcome"`
	VerifiedAt                    string `json:"verified_at"`
}

// CredentialPresentationVerifier verifies a policy-scoped BBS+ presentation.
// Implementations must not require PatientID disclosure unless policy
// explicitly mandates it.
type CredentialPresentationVerifier interface {
	VerifyCredentialPresentation(presentation []byte, policyID string) error
}

// BiometricComparisonVerifier performs a privacy-preserving in-memory
// biometric comparison. It must not persist the live sample or comparison
// value after returning.
type BiometricComparisonVerifier interface {
	VerifyBiometricComparison(value string) (bool, error)
}

// InPersonIdentityVerificationService implements the healthcare-organization
// side. It has no APC connection and does not retain raw biometric data.
type InPersonIdentityVerificationService struct {
	organizationDID    string
	policyID           string
	ibsVerifier        PseudonymIBSVerifier
	credentialVerifier CredentialPresentationVerifier
	biometricVerifier  BiometricComparisonVerifier
	bookingService     *AppointmentBookingService
	mu                 sync.Mutex
	usedSessions       map[string]struct{}
}

func NewInPersonIdentityVerificationService(organizationDID, policyID string, ibsVerifier PseudonymIBSVerifier, credentialVerifier CredentialPresentationVerifier, biometricVerifier BiometricComparisonVerifier, bookingService *AppointmentBookingService) (*InPersonIdentityVerificationService, error) {
	if organizationDID == "" || policyID == "" || ibsVerifier == nil || credentialVerifier == nil || biometricVerifier == nil || bookingService == nil {
		return nil, errors.New("organization DID, policy, verifiers, and booking service are required")
	}
	return &InPersonIdentityVerificationService{
		organizationDID: organizationDID, policyID: policyID, ibsVerifier: ibsVerifier,
		credentialVerifier: credentialVerifier, biometricVerifier: biometricVerifier,
		bookingService: bookingService, usedSessions: make(map[string]struct{}),
	}, nil
}

// Verify validates a current booking, the pseudonym-specific IBS signature,
// the PT, policy-scoped credential presentation, and biometric result. A
// session nonce is accepted only once.
func (s *InPersonIdentityVerificationService) Verify(request *InPersonIdentityVerificationRequest, now time.Time) (*IdentityVerificationRecord, error) {
	if s == nil || request == nil || request.Type != IdentityVerificationRequestType || request.PseudonymToken == nil {
		return nil, errors.New("invalid identity verification request")
	}
	if request.HealthcareOrganizationDID != s.organizationDID || request.AppointmentConfirmationCode == "" || request.SessionNonce == "" || request.PseudonymSignature == "" || len(request.CredentialPresentation) == 0 || request.BiometricComparisonValue == "" {
		return nil, errors.New("identity verification request is incomplete or for another organization")
	}
	pseudonym := request.PseudonymToken.Pseudonym
	if pseudonym == "" {
		return nil, errors.New("pseudonym token does not contain a pseudonym")
	}
	if _, err := s.bookingService.LookupBooking(request.AppointmentConfirmationCode, pseudonym); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if _, used := s.usedSessions[request.SessionNonce]; used {
		s.mu.Unlock()
		return nil, errors.New("identity verification session nonce was already used")
	}
	// Reserve the nonce before expensive verifications, so concurrent replayed
	// requests cannot both succeed. A failed session needs a fresh nonce.
	s.usedSessions[request.SessionNonce] = struct{}{}
	s.mu.Unlock()

	message, err := inPersonIdentityVerificationBytes(request)
	if err != nil {
		return nil, err
	}
	if err = s.ibsVerifier.VerifyPseudonymSignature(pseudonym, message, request.PseudonymSignature); err != nil {
		return nil, fmt.Errorf("verify pseudonym IBS signature: %w", err)
	}
	if err = VerifyPseudonymToken(request.PseudonymToken, now, s.organizationDID); err != nil {
		return nil, fmt.Errorf("verify pseudonym token: %w", err)
	}
	if request.PseudonymToken.PolicyID != s.policyID {
		return nil, errors.New("pseudonym token policy mismatch")
	}
	if err = s.credentialVerifier.VerifyCredentialPresentation(request.CredentialPresentation, s.policyID); err != nil {
		return nil, fmt.Errorf("verify patient credential presentation: %w", err)
	}
	matched, err := s.biometricVerifier.VerifyBiometricComparison(request.BiometricComparisonValue)
	if err != nil {
		return nil, fmt.Errorf("verify biometric comparison: %w", err)
	}
	if !matched {
		return nil, errors.New("biometric comparison failed")
	}
	return &IdentityVerificationRecord{
		Type:                          IdentityVerificationRecordType,
		ProtectedAppointmentReference: protectedAppointmentReference(request.AppointmentConfirmationCode),
		Pseudonym:                     pseudonym, Outcome: "verified", VerifiedAt: now.UTC().Format(time.RFC3339),
	}, nil
}

func SaveInPersonIdentityVerificationRequest(path string, request *InPersonIdentityVerificationRequest) error {
	if request == nil {
		return errors.New("identity verification request is nil")
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadInPersonIdentityVerificationRequest(path string) (*InPersonIdentityVerificationRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var request InPersonIdentityVerificationRequest
	if err = json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("decode identity verification request: %w", err)
	}
	return &request, nil
}

func SaveIdentityVerificationRecord(path string, record *IdentityVerificationRecord) error {
	if record == nil {
		return errors.New("identity verification record is nil")
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadIdentityVerificationRecord(path string) (*IdentityVerificationRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record IdentityVerificationRecord
	if err = json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode identity verification record: %w", err)
	}
	return &record, nil
}

func inPersonIdentityVerificationBytes(request *InPersonIdentityVerificationRequest) ([]byte, error) {
	credentialDigest := sha256.Sum256(request.CredentialPresentation)
	payload := struct {
		Domain, Type, ConfirmationCode, BiometricValue, CredentialDigest, TokenDigest, OrganizationDID, SessionNonce string
	}{
		Domain: "HIDM-IN-PERSON-IDENTITY-v1", Type: request.Type,
		ConfirmationCode: request.AppointmentConfirmationCode, BiometricValue: request.BiometricComparisonValue,
		CredentialDigest: base64.RawURLEncoding.EncodeToString(credentialDigest[:]),
		TokenDigest:      appointmentTokenDigestFromPseudonymToken(request.PseudonymToken),
		OrganizationDID:  request.HealthcareOrganizationDID, SessionNonce: request.SessionNonce,
	}
	return json.Marshal(payload)
}

func appointmentTokenDigestFromPseudonymToken(token *PseudonymToken) string {
	b, _ := json.Marshal(token)
	digest := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func protectedAppointmentReference(confirmationCode string) string {
	digest := sha256.Sum256([]byte("HIDM-APPOINTMENT-AUDIT-REFERENCE-v1\x00" + confirmationCode))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
