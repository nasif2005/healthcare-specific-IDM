package patientcredential

import "testing"

func TestCCIBSExtractSignAndVerify(t *testing.T) {
	a, err := NewCCIBSAuthority(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := a.Extract("pyn_test")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := CCIBSSign("pyn_test", key, []byte("booking transcript"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := CCIBSVerifier{MasterPublicKey: a.MasterPublicKey()}
	if err = v.VerifyPseudonymSignature("pyn_test", []byte("booking transcript"), sig); err != nil {
		t.Fatal(err)
	}
	if err = v.VerifyPseudonymSignature("pyn_test", []byte("tampered"), sig); err == nil {
		t.Fatal("tampered message accepted")
	}
}

func TestMeasurePatientCredentialIssuance(t *testing.T) {
	result, err := MeasurePatientCredentialIssuance(2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Workflow != "patient_credential_issuance" || result.Iterations != 2 {
		t.Fatal("incorrect measurement metadata")
	}
	if result.CommunicationBytes.Request == 0 || result.CommunicationBytes.Response == 0 || result.CommunicationBytes.Total != result.CommunicationBytes.Request+result.CommunicationBytes.Response {
		t.Fatal("invalid communication measurement")
	}
	if result.PersistentStorageBytes.Credential == 0 || result.PersistentStorageBytes.EncryptedSecret == 0 || result.PersistentStorageBytes.PatientTotal != result.PersistentStorageBytes.Credential+result.PersistentStorageBytes.EncryptedSecret {
		t.Fatal("invalid storage measurement")
	}
}

func TestMeasurePatientCredentialIssuanceRejectsZeroIterations(t *testing.T) {
	if _, err := MeasurePatientCredentialIssuance(0); err == nil {
		t.Fatal("zero iterations accepted")
	}
}

func TestMeasurePseudonymTokenIssuance(t *testing.T) {
	result, err := MeasurePseudonymTokenIssuance(2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Workflow != "pseudonym_token_issuance" || result.Iterations != 2 {
		t.Fatal("incorrect measurement metadata")
	}
	if result.CommunicationBytes.Request == 0 || result.CommunicationBytes.Response == 0 || result.CommunicationBytes.Total != result.CommunicationBytes.Request+result.CommunicationBytes.Response {
		t.Fatal("invalid communication measurement")
	}
	if result.PersistentStorageBytes.PseudonymToken == 0 || result.PersistentStorageBytes.PatientTotal != result.PersistentStorageBytes.PseudonymToken {
		t.Fatal("invalid storage measurement")
	}
}

func TestMeasureAppointmentTokenIssuance(t *testing.T) {
	result, err := MeasureAppointmentTokenIssuance(2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Workflow != "appointment_token_issuance" || result.Iterations != 2 {
		t.Fatal("incorrect measurement metadata")
	}
	communication := result.CommunicationBytes
	if communication.CredentialPresentationRequest == 0 || communication.IssuanceChallenge == 0 || communication.BlindRequest == 0 || communication.BlindResponse == 0 {
		t.Fatal("missing protocol-message measurement")
	}
	if communication.Request != communication.CredentialPresentationRequest+communication.BlindRequest || communication.Response != communication.IssuanceChallenge+communication.BlindResponse || communication.Total != communication.Request+communication.Response {
		t.Fatal("invalid communication measurement")
	}
	if result.PersistentStorageBytes.AppointmentToken == 0 || result.PersistentStorageBytes.PatientTotal != result.PersistentStorageBytes.AppointmentToken {
		t.Fatal("invalid storage measurement")
	}
}

func TestMeasureAppointmentBooking(t *testing.T) {
	result, err := MeasureAppointmentBooking(2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Workflow != "appointment_booking" || result.Iterations != 2 {
		t.Fatal("incorrect measurement metadata")
	}
	communication := result.CommunicationBytes
	if communication.BookingRequest == 0 || communication.BookingResponse == 0 || communication.Request != communication.BookingRequest || communication.Response != communication.BookingResponse || communication.Total != communication.Request+communication.Response {
		t.Fatal("invalid communication measurement")
	}
	storage := result.PersistentStorageBytes
	if storage.PatientScheduleRequest == 0 || storage.ProviderBookingRecord == 0 || storage.PatientTotal != storage.PatientScheduleRequest || storage.ProviderTotal != storage.ProviderBookingRecord {
		t.Fatal("invalid storage measurement")
	}
}

func TestMeasureAppointmentBookingRejectsZeroIterations(t *testing.T) {
	if _, err := MeasureAppointmentBooking(0); err == nil {
		t.Fatal("zero iterations accepted")
	}
}
