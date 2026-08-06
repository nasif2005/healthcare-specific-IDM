package patientcredential

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// PatientCredentialIssuanceMeasurement contains repeatable measurements for
// the patient-credential issuance workflow. Network sizes are the UTF-8 JSON
// payload sizes; transport headers, TLS, and database replication are outside
// the scope of this proof of concept.
type PatientCredentialIssuanceMeasurement struct {
	Workflow               string          `json:"workflow"`
	Iterations             int             `json:"iterations"`
	LatencyMilliseconds    LatencySummary  `json:"latency_milliseconds"`
	CommunicationBytes     Communication   `json:"communication_bytes"`
	PersistentStorageBytes CredentialStore `json:"persistent_storage_bytes"`
}

type LatencySummary struct {
	Min    float64 `json:"min"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	Max    float64 `json:"max"`
}

type Communication struct {
	Request  int `json:"request"`
	Response int `json:"response"`
	Total    int `json:"total"`
}

type CredentialStore struct {
	Credential      int `json:"patient_credential"`
	EncryptedSecret int `json:"encrypted_holder_secret"`
	PatientTotal    int `json:"patient_total"`
}

// PseudonymTokenIssuanceMeasurement contains measurements for the workflow
// that turns an already-held patient credential into a PTA-issued token.
type PseudonymTokenIssuanceMeasurement struct {
	Workflow               string         `json:"workflow"`
	Iterations             int            `json:"iterations"`
	LatencyMilliseconds    LatencySummary `json:"latency_milliseconds"`
	CommunicationBytes     Communication  `json:"communication_bytes"`
	PersistentStorageBytes TokenStore     `json:"persistent_storage_bytes"`
}

type TokenStore struct {
	PseudonymToken int `json:"pseudonym_token"`
	PatientTotal   int `json:"patient_total"`
}

// AppointmentTokenIssuanceMeasurement contains measurements for the
// credential-authenticated, partially blind appointment-token workflow.
type AppointmentTokenIssuanceMeasurement struct {
	Workflow               string                        `json:"workflow"`
	Iterations             int                           `json:"iterations"`
	LatencyMilliseconds    LatencySummary                `json:"latency_milliseconds"`
	CommunicationBytes     AppointmentTokenCommunication `json:"communication_bytes"`
	PersistentStorageBytes AppointmentTokenStore         `json:"persistent_storage_bytes"`
}

// AppointmentTokenCommunication retains every serialized protocol message.
// Request and response totals aggregate the patient-to-APC and APC-to-patient
// directions, respectively.
type AppointmentTokenCommunication struct {
	CredentialPresentationRequest int `json:"credential_presentation_request"`
	IssuanceChallenge             int `json:"issuance_challenge"`
	BlindRequest                  int `json:"blind_request"`
	BlindResponse                 int `json:"blind_response"`
	Request                       int `json:"request"`
	Response                      int `json:"response"`
	Total                         int `json:"total"`
}

type AppointmentTokenStore struct {
	AppointmentToken int `json:"appointment_token"`
	PatientTotal     int `json:"patient_total"`
}

// AppointmentBookingMeasurement reports the booking exchange after the
// patient has already obtained an appointment token. Communication is compact
// application-level JSON; HTTP/TLS/DIDComm framing and durable spent-token
// ledger implementation costs are outside this POC's scope.
type AppointmentBookingMeasurement struct {
	Workflow               string                    `json:"workflow"`
	Iterations             int                       `json:"iterations"`
	LatencyMilliseconds    LatencySummary            `json:"latency_milliseconds"`
	CommunicationBytes     AppointmentBookingTraffic `json:"communication_bytes"`
	PersistentStorageBytes AppointmentBookingStore   `json:"persistent_storage_bytes"`
}

type AppointmentBookingTraffic struct {
	BookingRequest  int `json:"booking_request"`
	BookingResponse int `json:"booking_response"`
	Request         int `json:"request"`
	Response        int `json:"response"`
	Total           int `json:"total"`
}

type AppointmentBookingStore struct {
	PatientScheduleRequest int `json:"patient_schedule_request"`
	ProviderBookingRecord  int `json:"provider_booking_record"`
	PatientTotal           int `json:"patient_total"`
	ProviderTotal          int `json:"provider_total"`
}

type InPersonIdentityVerificationMeasurement struct {
	Workflow               string                    `json:"workflow"`
	Iterations             int                       `json:"iterations"`
	LatencyMilliseconds    LatencySummary            `json:"latency_milliseconds"`
	CommunicationBytes     Communication             `json:"communication_bytes"`
	PersistentStorageBytes IdentityVerificationStore `json:"persistent_storage_bytes"`
}
type IdentityVerificationStore struct {
	PatientRequest int `json:"patient_request"`
	ProviderRecord int `json:"provider_record"`
	PatientTotal   int `json:"patient_total"`
	ProviderTotal  int `json:"provider_total"`
}

// pseudonymTokenIssuanceRequest is the application-level message sent to the
// PTA after it sends the challenge. It makes the POC's transmitted objects
// explicit for byte-size measurement.
type pseudonymTokenIssuanceRequest struct {
	Credential *Credential           `json:"credential"`
	Proof      *CredentialProof      `json:"selective_disclosure_proof"`
	Request    PseudonymTokenRequest `json:"token_request"`
}

type appointmentCredentialPresentationRequest struct {
	Credential *Credential      `json:"credential"`
	Proof      *CredentialProof `json:"selective_disclosure_proof"`
}

// MeasurePatientCredentialIssuance measures local link-secret and commitment
// generation, request serialization, issuer signing, response serialization,
// and holder-side signature verification. It excludes long-lived issuer key
// generation and filesystem I/O, which is reported through storage byte sizes.
func MeasurePatientCredentialIssuance(iterations int) (*PatientCredentialIssuanceMeasurement, error) {
	if iterations < 1 {
		return nil, errors.New("iterations must be at least one")
	}
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		return nil, err
	}
	latencies := make([]float64, 0, iterations)
	var communication Communication
	var storage CredentialStore
	for n := 0; n < iterations; n++ {
		started := time.Now()
		secret, err := NewRandomLinkSecret()
		if err != nil {
			return nil, err
		}
		commitment, err := NewLinkSecretCommitment(secret)
		if err != nil {
			return nil, err
		}
		req := PatientCredentialRequest{PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1", DateOfBirth: "1985-04-12", EligibilityStatus: "active", Jurisdiction: "CA-ON", LinkSecretCommitment: commitment}
		requestBytes, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		cred, err := issuer.Issue(req, "urn:uuid:hidm-measurement-credential-"+now.Format("20060102150405.000000000"), now, now.AddDate(1, 0, 0))
		if err != nil {
			return nil, err
		}
		responseBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		if err = issuer.Verify(cred, now); err != nil {
			return nil, err
		}
		latencies = append(latencies, float64(time.Since(started).Microseconds())/1000)

		credentialStorage, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return nil, err
		}
		walletKey := make([]byte, 32)
		if _, err = rand.Read(walletKey); err != nil {
			return nil, err
		}
		secretStorage, err := holderSecretEnvelopeJSON(cred.CredentialID, secret, walletKey)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			communication = Communication{Request: len(requestBytes), Response: len(responseBytes), Total: len(requestBytes) + len(responseBytes)}
			storage = CredentialStore{Credential: len(credentialStorage), EncryptedSecret: len(secretStorage), PatientTotal: len(credentialStorage) + len(secretStorage)}
		}
	}
	return &PatientCredentialIssuanceMeasurement{Workflow: "patient_credential_issuance", Iterations: iterations, LatencyMilliseconds: summarizeMilliseconds(latencies), CommunicationBytes: communication, PersistentStorageBytes: storage}, nil
}

// MeasurePseudonymTokenIssuance measures challenge generation, selective
// disclosure proof generation, pseudonym/PBP creation, request serialization,
// PTA verification and signing, response serialization, and patient-side
// token verification. Credential and PTA signing-key setup are excluded as
// long-lived preconditions. The request size includes the credential because
// this POC passes it to the verifier alongside the selective-disclosure proof.
func MeasurePseudonymTokenIssuance(iterations int) (*PseudonymTokenIssuanceMeasurement, error) {
	if iterations < 1 {
		return nil, errors.New("iterations must be at least one")
	}
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		return nil, err
	}
	secret, err := NewRandomLinkSecret()
	if err != nil {
		return nil, err
	}
	commitment, err := NewLinkSecretCommitment(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	credential, err := issuer.Issue(PatientCredentialRequest{PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1", DateOfBirth: "1985-04-12", EligibilityStatus: "active", Jurisdiction: "CA-ON", LinkSecretCommitment: commitment}, "urn:uuid:hidm-measurement-credential", now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	holder := &Holder{Credential: credential, LinkSecret: secret}
	pta, err := NewPTAService(issuer, rand.Reader)
	if err != nil {
		return nil, err
	}
	latencies := make([]float64, 0, iterations)
	var communication Communication
	var storage TokenStore
	for n := 0; n < iterations; n++ {
		started := time.Now()
		nonce, err := pta.NewChallenge(rand.Reader)
		if err != nil {
			return nil, err
		}
		context := "measurement-pta-session-" + time.Now().UTC().Format("20060102150405.000000000")
		proof, err := holder.CreatePatientIDProofForNonce(context, nonce, rand.Reader)
		if err != nil {
			return nil, err
		}
		pseudonym, bindingProof, err := NewPseudonym(credential.Subject.PatientID, credential.CredentialID, "hrr.example.org", "ehr-read-v1", nonce, rand.Reader)
		if err != nil {
			return nil, err
		}
		issuedAt := time.Now().UTC()
		req := PseudonymTokenRequest{Pseudonym: pseudonym, BindingProof: bindingProof, CredentialID: credential.CredentialID, Audience: "hrr.example.org", PolicyID: "ehr-read-v1", ExpiresAt: issuedAt.Add(24 * time.Hour)}
		requestBytes, err := json.Marshal(pseudonymTokenIssuanceRequest{Credential: credential, Proof: proof, Request: req})
		if err != nil {
			return nil, err
		}
		token, err := pta.IssuePseudonymToken(credential, proof, nonce, context, req, issuedAt, "urn:uuid:hidm-measurement-pseudonym-token-"+issuedAt.Format("20060102150405.000000000"))
		if err != nil {
			return nil, err
		}
		responseBytes, err := json.Marshal(token)
		if err != nil {
			return nil, err
		}
		if err = VerifyPseudonymToken(token, issuedAt, "hrr.example.org"); err != nil {
			return nil, err
		}
		latencies = append(latencies, float64(time.Since(started).Microseconds())/1000)
		tokenStorage, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return nil, err
		}
		if n == 0 {
			communication = Communication{Request: len(requestBytes), Response: len(responseBytes), Total: len(requestBytes) + len(responseBytes)}
			storage = TokenStore{PseudonymToken: len(tokenStorage), PatientTotal: len(tokenStorage)}
		}
	}
	return &PseudonymTokenIssuanceMeasurement{Workflow: "pseudonym_token_issuance", Iterations: iterations, LatencyMilliseconds: summarizeMilliseconds(latencies), CommunicationBytes: communication, PersistentStorageBytes: storage}, nil
}

// MeasureAppointmentTokenIssuance measures the issuance workflow from the
// APC credential challenge through local token finalization and verification.
// Credential and appointment-authority key setup are long-lived preconditions
// and are excluded. Communication is measured as compact JSON for all four
// protocol messages; the final token is created locally and stored by the
// patient rather than transmitted to the APC.
func MeasureAppointmentTokenIssuance(iterations int) (*AppointmentTokenIssuanceMeasurement, error) {
	if iterations < 1 {
		return nil, errors.New("iterations must be at least one")
	}
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		return nil, err
	}
	secret, err := NewRandomLinkSecret()
	if err != nil {
		return nil, err
	}
	commitment, err := NewLinkSecretCommitment(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	credential, err := issuer.Issue(PatientCredentialRequest{PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1", DateOfBirth: "1985-04-12", EligibilityStatus: "active", Jurisdiction: "CA-ON", LinkSecretCommitment: commitment}, "urn:uuid:hidm-measurement-credential", now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	holder := &Holder{Credential: credential, LinkSecret: secret}
	authority, err := NewAppointmentTokenAuthority(issuer)
	if err != nil {
		return nil, err
	}
	latencies := make([]float64, 0, iterations)
	var communication AppointmentTokenCommunication
	var storage AppointmentTokenStore
	for n := 0; n < iterations; n++ {
		started := time.Now()
		nonce, err := authority.NewCredentialChallenge(rand.Reader)
		if err != nil {
			return nil, err
		}
		context := "measurement-apc-session-" + time.Now().UTC().Format("20060102150405.000000000")
		proof, err := holder.CreatePatientIDProofForNonce(context, nonce, rand.Reader)
		if err != nil {
			return nil, err
		}
		presentationBytes, err := json.Marshal(appointmentCredentialPresentationRequest{Credential: credential, Proof: proof})
		if err != nil {
			return nil, err
		}
		issuedAt := time.Now().UTC()
		challenge, err := authority.BeginIssuance(credential, proof, nonce, context, issuedAt, issuedAt.Add(24*time.Hour), rand.Reader)
		if err != nil {
			return nil, err
		}
		challengeBytes, err := json.Marshal(challenge)
		if err != nil {
			return nil, err
		}
		ati, err := NewAppointmentTokenID(rand.Reader)
		if err != nil {
			return nil, err
		}
		blindRequest, state, err := PrepareBlindAppointmentToken(challenge, ati)
		if err != nil {
			return nil, err
		}
		blindRequestBytes, err := json.Marshal(blindRequest)
		if err != nil {
			return nil, err
		}
		blindResponse, err := authority.SignBlindAppointmentToken(blindRequest)
		if err != nil {
			return nil, err
		}
		blindResponseBytes, err := json.Marshal(blindResponse)
		if err != nil {
			return nil, err
		}
		token, err := FinalizeAppointmentToken(challenge, state, blindResponse, authority.PublicKey())
		if err != nil {
			return nil, err
		}
		if err = VerifyAppointmentToken(token, issuedAt); err != nil {
			return nil, err
		}
		latencies = append(latencies, float64(time.Since(started).Microseconds())/1000)
		tokenStorage, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return nil, err
		}
		if n == 0 {
			communication = AppointmentTokenCommunication{CredentialPresentationRequest: len(presentationBytes), IssuanceChallenge: len(challengeBytes), BlindRequest: len(blindRequestBytes), BlindResponse: len(blindResponseBytes), Request: len(presentationBytes) + len(blindRequestBytes), Response: len(challengeBytes) + len(blindResponseBytes), Total: len(presentationBytes) + len(challengeBytes) + len(blindRequestBytes) + len(blindResponseBytes)}
			storage = AppointmentTokenStore{AppointmentToken: len(tokenStorage), PatientTotal: len(tokenStorage)}
		}
	}
	return &AppointmentTokenIssuanceMeasurement{Workflow: "appointment_token_issuance", Iterations: iterations, LatencyMilliseconds: summarizeMilliseconds(latencies), CommunicationBytes: communication, PersistentStorageBytes: storage}, nil
}

// MeasureAppointmentBooking measures the local booking exchange: request
// serialization, pseudonym-signature and appointment-token verification,
// one-time token consumption, booking-record creation, and confirmation
// serialization. Appointment-token issuance and key extraction are
// preconditions; the patient-side CC-IBS signing and provider-side pairing
// verification are included in the timed booking workflow.
func MeasureAppointmentBooking(iterations int) (*AppointmentBookingMeasurement, error) {
	if iterations < 1 {
		return nil, errors.New("iterations must be at least one")
	}
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		return nil, err
	}
	secret, err := NewRandomLinkSecret()
	if err != nil {
		return nil, err
	}
	commitment, err := NewLinkSecretCommitment(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	credential, err := issuer.Issue(PatientCredentialRequest{PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1", DateOfBirth: "1985-04-12", EligibilityStatus: "active", Jurisdiction: "CA-ON", LinkSecretCommitment: commitment}, "urn:uuid:hidm-measurement-booking-credential", now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	holder := &Holder{Credential: credential, LinkSecret: secret}
	authority, err := NewAppointmentTokenAuthority(issuer)
	if err != nil {
		return nil, err
	}
	ibsAuthority, err := NewCCIBSAuthority(rand.Reader)
	if err != nil {
		return nil, err
	}
	latencies := make([]float64, 0, iterations)
	var communication AppointmentBookingTraffic
	var storage AppointmentBookingStore
	for n := 0; n < iterations; n++ {
		inputs := make([]bookingMeasurementInput, appointmentBookingTimingBatch)
		for i := range inputs {
			token, bookingTime, err := issueMeasurementAppointmentToken(authority, holder, credential)
			if err != nil {
				return nil, err
			}
			privateKey, err := ibsAuthority.Extract("pyn_measurement_visit")
			if err != nil {
				return nil, err
			}
			request := &AppointmentScheduleRequest{Type: AppointmentScheduleRequestType, PAI: PseudonymAccessInformation{Pseudonym: "pyn_measurement_visit", ReEncryptionKey: "rk_measurement", PatientIDCiphertext: "ct_measurement"}, AppointmentToken: token, ScheduleInfo: AppointmentScheduleInfo{Date: "2026-08-15", TimeSlot: "10:30", Service: "primary-care"}, HealthcareOrganizationDID: "did:web:clinic.example.org", SessionNonce: "booking-measurement-session"}
			service, err := NewAppointmentBookingService("did:web:clinic.example.org", CCIBSVerifier{MasterPublicKey: ibsAuthority.MasterPublicKey()}, NewAppointmentTokenUsageLedger())
			if err != nil {
				return nil, err
			}
			inputs[i] = bookingMeasurementInput{request: request, privateKey: privateKey, service: service, bookingTime: bookingTime}
		}

		started := time.Now()
		var requestBytes, responseBytes []byte
		var record *AppointmentBookingRecord
		for i, input := range inputs {
			message, err := appointmentScheduleRequestBytes(input.request)
			if err != nil {
				return nil, err
			}
			input.request.PseudonymSignature, err = CCIBSSign(input.request.PAI.Pseudonym, input.privateKey, message, rand.Reader)
			if err != nil {
				return nil, err
			}
			requestBytes, err = json.Marshal(input.request)
			if err != nil {
				return nil, err
			}
			record, err = input.service.Book(input.request, input.bookingTime, rand.Reader)
			if err != nil {
				return nil, err
			}
			responseBytes, err = json.Marshal(appointmentBookingConfirmation{AppointmentConfirmationCode: record.AppointmentConfirmationCode})
			if err != nil {
				return nil, err
			}
			if i == 0 {
				communication = AppointmentBookingTraffic{BookingRequest: len(requestBytes), BookingResponse: len(responseBytes), Request: len(requestBytes), Response: len(responseBytes), Total: len(requestBytes) + len(responseBytes)}
			}
		}
		latencies = append(latencies, float64(time.Since(started).Nanoseconds())/1_000_000/appointmentBookingTimingBatch)

		patientStorage, err := json.MarshalIndent(inputs[0].request, "", "  ")
		if err != nil {
			return nil, err
		}
		providerStorage, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return nil, err
		}
		if n == 0 {
			storage = AppointmentBookingStore{PatientScheduleRequest: len(patientStorage), ProviderBookingRecord: len(providerStorage), PatientTotal: len(patientStorage), ProviderTotal: len(providerStorage)}
		}
	}
	return &AppointmentBookingMeasurement{Workflow: "appointment_booking", Iterations: iterations, LatencyMilliseconds: summarizeMilliseconds(latencies), CommunicationBytes: communication, PersistentStorageBytes: storage}, nil
}

// MeasureInPersonIdentityVerification measures signing, request serialization,
// real CC-IBS verification, pseudonym-token verification, booking lookup, and
// the configured credential-presentation and biometric-verifier boundaries.
// Full BBS+ presentation and biometric matcher implementations remain outside
// this POC and are represented by successful local boundary verifiers.
func MeasureInPersonIdentityVerification(iterations int) (*InPersonIdentityVerificationMeasurement, error) {
	if iterations < 1 {
		return nil, errors.New("iterations must be at least one")
	}
	issuer, err := NewIssuer("did:web:apc.example.org")
	if err != nil {
		return nil, err
	}
	secret, err := NewRandomLinkSecret()
	if err != nil {
		return nil, err
	}
	commitment, err := NewLinkSecretCommitment(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	cred, err := issuer.Issue(PatientCredentialRequest{PatientID: "APC-00012345", PatientReference: "opaque-patient-reference-1", DateOfBirth: "1985-04-12", EligibilityStatus: "active", Jurisdiction: "CA-ON", LinkSecretCommitment: commitment}, "urn:uuid:hidm-measurement-identity-credential", now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	holder := &Holder{Credential: cred, LinkSecret: secret}
	pta, err := NewPTAService(issuer, rand.Reader)
	if err != nil {
		return nil, err
	}
	atAuthority, err := NewAppointmentTokenAuthority(issuer)
	if err != nil {
		return nil, err
	}
	ibsAuthority, err := NewCCIBSAuthority(rand.Reader)
	if err != nil {
		return nil, err
	}
	latencies := make([]float64, 0, iterations)
	var traffic Communication
	var storage IdentityVerificationStore
	for n := 0; n < iterations; n++ {
		pt, err := issueMeasurementPseudonymToken(pta, holder, cred)
		if err != nil {
			return nil, err
		}
		at, bookingTime, err := issueMeasurementAppointmentToken(atAuthority, holder, cred)
		if err != nil {
			return nil, err
		}
		key, err := ibsAuthority.Extract(pt.Pseudonym)
		if err != nil {
			return nil, err
		}
		booking, err := NewAppointmentBookingService("did:web:clinic.example.org", CCIBSVerifier{MasterPublicKey: ibsAuthority.MasterPublicKey()}, NewAppointmentTokenUsageLedger())
		if err != nil {
			return nil, err
		}
		bookReq := &AppointmentScheduleRequest{Type: AppointmentScheduleRequestType, PAI: PseudonymAccessInformation{Pseudonym: pt.Pseudonym, ReEncryptionKey: "rk_measurement", PatientIDCiphertext: "ct_measurement"}, AppointmentToken: at, ScheduleInfo: AppointmentScheduleInfo{Date: "2026-08-15", TimeSlot: "10:30", Service: "primary-care"}, HealthcareOrganizationDID: "did:web:clinic.example.org", SessionNonce: "booking-session"}
		bookMsg, _ := appointmentScheduleRequestBytes(bookReq)
		bookReq.PseudonymSignature, err = CCIBSSign(pt.Pseudonym, key, bookMsg, rand.Reader)
		if err != nil {
			return nil, err
		}
		bookRecord, err := booking.Book(bookReq, bookingTime, rand.Reader)
		if err != nil {
			return nil, err
		}
		service, err := NewInPersonIdentityVerificationService("did:web:clinic.example.org", "visit-identity-v1", CCIBSVerifier{MasterPublicKey: ibsAuthority.MasterPublicKey()}, measurementCredentialPresentationVerifier{}, measurementBiometricVerifier{}, booking)
		if err != nil {
			return nil, err
		}
		req := &InPersonIdentityVerificationRequest{Type: IdentityVerificationRequestType, AppointmentConfirmationCode: bookRecord.AppointmentConfirmationCode, BiometricComparisonValue: "matched", CredentialPresentation: json.RawMessage(`{"proof":"measurement-valid"}`), PseudonymToken: pt, HealthcareOrganizationDID: "did:web:clinic.example.org", SessionNonce: "identity-session"}
		started := time.Now()
		msg, err := inPersonIdentityVerificationBytes(req)
		if err != nil {
			return nil, err
		}
		req.PseudonymSignature, err = CCIBSSign(pt.Pseudonym, key, msg, rand.Reader)
		if err != nil {
			return nil, err
		}
		requestBytes, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		record, err := service.Verify(req, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		responseBytes, err := json.Marshal(struct {
			Outcome string `json:"outcome"`
		}{record.Outcome})
		if err != nil {
			return nil, err
		}
		latencies = append(latencies, float64(time.Since(started).Nanoseconds())/1_000_000)
		if n == 0 {
			patient, _ := json.MarshalIndent(req, "", "  ")
			provider, _ := json.MarshalIndent(record, "", "  ")
			traffic = Communication{Request: len(requestBytes), Response: len(responseBytes), Total: len(requestBytes) + len(responseBytes)}
			storage = IdentityVerificationStore{PatientRequest: len(patient), ProviderRecord: len(provider), PatientTotal: len(patient), ProviderTotal: len(provider)}
		}
	}
	return &InPersonIdentityVerificationMeasurement{Workflow: "in_person_identity_verification", Iterations: iterations, LatencyMilliseconds: summarizeMilliseconds(latencies), CommunicationBytes: traffic, PersistentStorageBytes: storage}, nil
}

type measurementCredentialPresentationVerifier struct{}

func (measurementCredentialPresentationVerifier) VerifyCredentialPresentation(p []byte, policy string) error {
	if policy != "visit-identity-v1" || string(p) != `{"proof":"measurement-valid"}` {
		return errors.New("invalid measurement presentation")
	}
	return nil
}

type measurementBiometricVerifier struct{}

func (measurementBiometricVerifier) VerifyBiometricComparison(v string) (bool, error) {
	return v == "matched", nil
}
func issueMeasurementPseudonymToken(pta *PTAService, holder *Holder, cred *Credential) (*PseudonymToken, error) {
	now := time.Now().UTC()
	nonce, err := pta.NewChallenge(rand.Reader)
	if err != nil {
		return nil, err
	}
	context := "measurement-identity-" + now.Format("20060102150405.000000000")
	proof, err := holder.CreatePatientIDProofForNonce(context, nonce, rand.Reader)
	if err != nil {
		return nil, err
	}
	pseudonym, binding, err := NewPseudonym(cred.Subject.PatientID, cred.CredentialID, "did:web:clinic.example.org", "visit-identity-v1", nonce, rand.Reader)
	if err != nil {
		return nil, err
	}
	return pta.IssuePseudonymToken(cred, proof, nonce, context, PseudonymTokenRequest{Pseudonym: pseudonym, BindingProof: binding, CredentialID: cred.CredentialID, Audience: "did:web:clinic.example.org", PolicyID: "visit-identity-v1", ExpiresAt: now.Add(time.Hour)}, now, "urn:uuid:hidm-measurement-identity-token")
}

// Timing a batch avoids zero-duration samples on Windows' coarse wall clock;
// every batch contains independent, fresh one-time appointment tokens.
const appointmentBookingTimingBatch = 10

type bookingMeasurementInput struct {
	request     *AppointmentScheduleRequest
	privateKey  []byte
	service     *AppointmentBookingService
	bookingTime time.Time
}

type appointmentBookingConfirmation struct {
	AppointmentConfirmationCode string `json:"appointment_confirmation_code"`
}

func issueMeasurementAppointmentToken(authority *AppointmentTokenAuthority, holder *Holder, credential *Credential) (*AppointmentToken, time.Time, error) {
	now := time.Now().UTC()
	nonce, err := authority.NewCredentialChallenge(rand.Reader)
	if err != nil {
		return nil, now, err
	}
	context := "measurement-booking-token-" + now.Format("20060102150405.000000000")
	proof, err := holder.CreatePatientIDProofForNonce(context, nonce, rand.Reader)
	if err != nil {
		return nil, now, err
	}
	challenge, err := authority.BeginIssuance(credential, proof, nonce, context, now, now.Add(24*time.Hour), rand.Reader)
	if err != nil {
		return nil, now, err
	}
	ati, err := NewAppointmentTokenID(rand.Reader)
	if err != nil {
		return nil, now, err
	}
	blindRequest, state, err := PrepareBlindAppointmentToken(challenge, ati)
	if err != nil {
		return nil, now, err
	}
	blindResponse, err := authority.SignBlindAppointmentToken(blindRequest)
	if err != nil {
		return nil, now, err
	}
	token, err := FinalizeAppointmentToken(challenge, state, blindResponse, authority.PublicKey())
	if err != nil {
		return nil, now, err
	}
	return token, now, nil
}

func holderSecretEnvelopeJSON(credentialID string, secret, walletKey []byte) ([]byte, error) {
	aead, err := newWalletAEAD(walletKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, secret, []byte(credentialID))
	envelope := HolderSecretEnvelope{Version: 1, CredentialID: credentialID, Cipher: "AES-256-GCM", Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(sealed)}
	return json.MarshalIndent(envelope, "", "  ")
}

func summarizeMilliseconds(values []float64) LatencySummary {
	sort.Float64s(values)
	total := 0.0
	for _, value := range values {
		total += value
	}
	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + values[len(values)/2]) / 2
	}
	p95Index := int(float64(len(values)-1)*0.95 + 0.5)
	return LatencySummary{Min: values[0], Mean: total / float64(len(values)), Median: median, P95: values[p95Index], Max: values[len(values)-1]}
}
