package patientcredential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	AppointmentScheduleRequestType = "HIDMAppointmentScheduleRequest-v1"
	AppointmentBookingRecordType   = "HIDMAppointmentBookingRecord-v1"
)

// PseudonymAccessInformation is the patient-controlled PAI presented to the
// intended healthcare organization. PatientID is deliberately absent.
type PseudonymAccessInformation struct {
	Pseudonym           string `json:"pseudonym"`
	ReEncryptionKey     string `json:"re_encryption_key"`
	PatientIDCiphertext string `json:"patient_id_ciphertext"`
}

type AppointmentScheduleInfo struct {
	Date     string `json:"date"`
	TimeSlot string `json:"time_slot"`
	Service  string `json:"service"`
}

// AppointmentScheduleRequest is stored in the patient wallet. Its
// PseudonymSignature is opaque here because Cha--Cheon IBS extraction and
// signing are a separate module from this POC.
type AppointmentScheduleRequest struct {
	Type                      string                     `json:"type"`
	PAI                       PseudonymAccessInformation `json:"pai"`
	AppointmentToken          *AppointmentToken          `json:"appointment_token"`
	ScheduleInfo              AppointmentScheduleInfo    `json:"schedule_info"`
	HealthcareOrganizationDID string                     `json:"healthcare_organization_did"`
	SessionNonce              string                     `json:"session_nonce"`
	PseudonymSignature        string                     `json:"pseudonym_signature"`
}

// AppointmentBookingRecord is stored by the healthcare organization. It does
// not retain the raw ATI: TokenUseReference is a SHA-256 reference to the
// high-entropy UUIDv4 ATI used by the one-time-use ledger.
type AppointmentBookingRecord struct {
	Type                        string                  `json:"type"`
	AppointmentConfirmationCode string                  `json:"appointment_confirmation_code"`
	Pseudonym                   string                  `json:"pseudonym"`
	ScheduleInfo                AppointmentScheduleInfo `json:"schedule_info"`
	TokenUseReference           string                  `json:"token_use_reference"`
	BookedAt                    string                  `json:"booked_at"`
	TokenExpiresAt              string                  `json:"token_expires_at"`
}

// PseudonymIBSVerifier is the integration boundary for a Cha--Cheon IBS
// implementation. Booking is rejected unless a verifier is provided; the
// POC never substitutes another signature scheme while labelling it IBS.
type PseudonymIBSVerifier interface {
	VerifyPseudonymSignature(pseudonym string, message []byte, signature string) error
}

// AppointmentBookingService is the healthcare-organization booking role.
// It has no connection to the APC and learns the ATI only from the token the
// patient spends.
type AppointmentBookingService struct {
	organizationDID string
	ibsVerifier     PseudonymIBSVerifier
	usageLedger     *AppointmentTokenUsageLedger
	mu              sync.Mutex
	bookings        map[string]*AppointmentBookingRecord
}

func NewAppointmentBookingService(organizationDID string, verifier PseudonymIBSVerifier, usageLedger *AppointmentTokenUsageLedger) (*AppointmentBookingService, error) {
	if organizationDID == "" || verifier == nil || usageLedger == nil {
		return nil, errors.New("organization DID, IBS verifier, and usage ledger are required")
	}
	return &AppointmentBookingService{organizationDID: organizationDID, ibsVerifier: verifier, usageLedger: usageLedger, bookings: make(map[string]*AppointmentBookingRecord)}, nil
}

// Book verifies the pseudonym signature and the APC-issued appointment token,
// then atomically consumes the ATI. A successful call returns the record that
// the provider may persist; a repeated ATI is rejected.
func (s *AppointmentBookingService) Book(request *AppointmentScheduleRequest, now time.Time, reader io.Reader) (*AppointmentBookingRecord, error) {
	if s == nil || request == nil || request.Type != AppointmentScheduleRequestType || request.AppointmentToken == nil {
		return nil, errors.New("invalid appointment scheduling request")
	}
	if request.HealthcareOrganizationDID != s.organizationDID || request.PAI.Pseudonym == "" || request.SessionNonce == "" || request.PseudonymSignature == "" {
		return nil, errors.New("appointment scheduling request is incomplete or for another organization")
	}
	if request.ScheduleInfo.Date == "" || request.ScheduleInfo.TimeSlot == "" || request.ScheduleInfo.Service == "" {
		return nil, errors.New("appointment schedule information is incomplete")
	}
	message, err := appointmentScheduleRequestBytes(request)
	if err != nil {
		return nil, err
	}
	if err = s.ibsVerifier.VerifyPseudonymSignature(request.PAI.Pseudonym, message, request.PseudonymSignature); err != nil {
		return nil, fmt.Errorf("verify pseudonym IBS signature: %w", err)
	}
	confirmationCode, err := NewAppointmentConfirmationCode(reader)
	if err != nil {
		return nil, err
	}
	// Consume validates the APC signature and expiry immediately before the
	// booking is committed, preventing a second successful booking with ATI.
	if err = s.usageLedger.Consume(request.AppointmentToken, now); err != nil {
		return nil, err
	}
	record := &AppointmentBookingRecord{
		Type: AppointmentBookingRecordType, AppointmentConfirmationCode: confirmationCode,
		Pseudonym: request.PAI.Pseudonym, ScheduleInfo: request.ScheduleInfo,
		TokenUseReference: appointmentTokenUseReference(request.AppointmentToken.ATI),
		BookedAt:          now.UTC().Format(time.RFC3339), TokenExpiresAt: request.AppointmentToken.CommonInfo.ExpiresAt,
	}
	s.mu.Lock()
	s.bookings[confirmationCode] = record
	s.mu.Unlock()
	return record, nil
}

// LookupBooking returns a copy of an active local booking record. It is used
// by the in-person verification service; the raw confirmation code is never
// written to its audit record.
func (s *AppointmentBookingService) LookupBooking(confirmationCode, pseudonym string) (*AppointmentBookingRecord, error) {
	if s == nil || confirmationCode == "" || pseudonym == "" {
		return nil, errors.New("confirmation code and pseudonym are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.bookings[confirmationCode]
	if !ok || record.Pseudonym != pseudonym {
		return nil, errors.New("active appointment booking was not found")
	}
	copy := *record
	return &copy, nil
}

func NewAppointmentConfirmationCode(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	b := make([]byte, 18)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", err
	}
	return "acc_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func SaveAppointmentScheduleRequest(path string, request *AppointmentScheduleRequest) error {
	if request == nil {
		return errors.New("appointment scheduling request is nil")
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadAppointmentScheduleRequest(path string) (*AppointmentScheduleRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var request AppointmentScheduleRequest
	if err = json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("decode appointment scheduling request: %w", err)
	}
	return &request, nil
}

func SaveAppointmentBookingRecord(path string, record *AppointmentBookingRecord) error {
	if record == nil {
		return errors.New("appointment booking record is nil")
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadAppointmentBookingRecord(path string) (*AppointmentBookingRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record AppointmentBookingRecord
	if err = json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode appointment booking record: %w", err)
	}
	return &record, nil
}

func appointmentScheduleRequestBytes(request *AppointmentScheduleRequest) ([]byte, error) {
	payload := struct {
		Domain, Type, Pseudonym, ReEncryptionKey, PatientIDCiphertext, TokenDigest, Date, TimeSlot, Service, OrganizationDID, SessionNonce string
	}{
		Domain: "HIDM-APPOINTMENT-BOOKING-v1", Type: request.Type, Pseudonym: request.PAI.Pseudonym,
		ReEncryptionKey: request.PAI.ReEncryptionKey, PatientIDCiphertext: request.PAI.PatientIDCiphertext,
		TokenDigest: appointmentTokenDigest(request.AppointmentToken), Date: request.ScheduleInfo.Date,
		TimeSlot: request.ScheduleInfo.TimeSlot, Service: request.ScheduleInfo.Service,
		OrganizationDID: request.HealthcareOrganizationDID, SessionNonce: request.SessionNonce,
	}
	return json.Marshal(payload)
}

func appointmentTokenDigest(token *AppointmentToken) string {
	b, _ := json.Marshal(token)
	digest := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func appointmentTokenUseReference(ati string) string {
	digest := sha256.Sum256([]byte("HIDM-ATI-USE-REFERENCE-v1\x00" + ati))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
