// Package patientcredential implements the APC-issued BBS+ patient credential
// proof of concept used by the HIDM workflow.
//
// This is an application credential format, not a claim of W3C VC/BBS
// interoperability. The signed message order is deliberately fixed and is
// part of the credential so that JSON map ordering never affects verification.
package patientcredential

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/etclab/kryptology/pkg/core/curves"
	"github.com/etclab/kryptology/pkg/signatures/bbs"
	"github.com/etclab/kryptology/pkg/signatures/common"
	"github.com/gtank/merlin"
)

const (
	Schema             = "https://example.org/schemas/hidm-patient-v1"
	CredentialType     = "HIDMPatientCredential"
	SignatureType      = "BbsBlsSignature2020-PoC"
	MessageDomain      = "HIDM-PATIENT-CREDENTIAL-v1"
	SignatureKeyMethod = "apc-bbs-key-1"
)

var MessageOrder = []string{
	"credential_id", "issuer", "issuance_date", "expiration_date",
	"patient_id", "patient_reference", "date_of_birth", "eligibility_status",
	"jurisdiction", "link_secret_commitment",
}

type Subject struct {
	PatientID            string `json:"patient_id"`
	PatientReference     string `json:"patient_reference"`
	DateOfBirth          string `json:"date_of_birth"`
	EligibilityStatus    string `json:"eligibility_status"`
	Jurisdiction         string `json:"jurisdiction"`
	LinkSecretCommitment string `json:"link_secret_commitment"`
}

type Proof struct {
	Type               string   `json:"type"`
	Cryptosuite        string   `json:"cryptosuite"`
	VerificationMethod string   `json:"verification_method"`
	Created            string   `json:"created"`
	ProofPurpose       string   `json:"proof_purpose"`
	MessageOrder       []string `json:"message_order"`
	PublicKey          string   `json:"public_key"`
	ProofValue         string   `json:"proof_value"`
}

type Credential struct {
	CredentialID   string   `json:"credential_id"`
	Type           []string `json:"type"`
	Issuer         string   `json:"issuer"`
	IssuanceDate   string   `json:"issuance_date"`
	ExpirationDate string   `json:"expiration_date"`
	Schema         string   `json:"schema"`
	Subject        Subject  `json:"credential_subject"`
	Proof          Proof    `json:"proof"`
}

type PatientCredentialRequest struct {
	PatientID            string `json:"patient_id"`
	PatientReference     string `json:"patient_reference"`
	DateOfBirth          string `json:"date_of_birth"`
	EligibilityStatus    string `json:"eligibility_status"`
	Jurisdiction         string `json:"jurisdiction"`
	LinkSecretCommitment string `json:"link_secret_commitment"`
}

// CredentialProof is the holder's selective-disclosure proof. In this POC the
// PTA receives only patient_id; all other signed messages, including the link
// secret commitment, remain hidden.
type CredentialProof struct {
	Type         string            `json:"type"`
	CredentialID string            `json:"credential_id"`
	Revealed     map[string]string `json:"revealed"`
	Nonce        string            `json:"nonce"`
	Challenge    string            `json:"challenge"`
	ProofValue   string            `json:"proof_value"`
}

// Holder represents patient-side credential material. The raw link secret is
// deliberately kept separate from the credential and is never serialized by
// this package.
type Holder struct {
	Credential *Credential
	LinkSecret []byte
}

// PTA is the verifier role. It issues fresh challenges and verifies proofs;
// it does not hold the APC signing secret or the patient's link secret.
type PTA struct {
	issuer *Issuer
	used   map[string]struct{}
}

func NewPTA(apcVerifier *Issuer) *PTA {
	return &PTA{issuer: apcVerifier, used: make(map[string]struct{})}
}

func (p *PTA) NewChallenge(reader io.Reader) ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := io.ReadFull(reader, nonce)
	return nonce, err
}

func (p *PTA) VerifyPatientIDProof(cred *Credential, proof *CredentialProof, context string, nonce []byte) (string, error) {
	if p == nil || p.issuer == nil {
		return "", errors.New("PTA verifier is not configured")
	}
	if len(nonce) == 0 {
		return "", errors.New("invalid PTA nonce")
	}
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	expectedNonce := curve.Scalar.Hash(nonce)
	expectedNonceEncoded := base64.RawURLEncoding.EncodeToString(expectedNonce.Bytes())
	if proof == nil || !EqualCommitment(proof.Nonce, expectedNonceEncoded) {
		return "", errors.New("proof does not contain the PTA challenge")
	}
	key := proof.CredentialID + ":" + proof.Nonce
	if _, exists := p.used[key]; exists {
		return "", errors.New("proof challenge has already been used")
	}
	patientID, err := p.issuer.VerifyPatientIDProof(cred, proof, context)
	if err != nil {
		return "", err
	}
	p.used[key] = struct{}{}
	return patientID, nil
}

type Issuer struct {
	issuer string
	curve  *curves.PairingCurve
	pk     *bbs.PublicKey
	sk     *bbs.SecretKey
}

func NewIssuer(issuer string) (*Issuer, error) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := bbs.NewKeys(curve)
	if err != nil {
		return nil, fmt.Errorf("create BBS+ issuer key: %w", err)
	}
	return &Issuer{issuer: issuer, curve: curve, pk: pk, sk: sk}, nil
}

func (i *Issuer) PublicKeyBytes() ([]byte, error) { return i.pk.MarshalBinary() }

func (i *Issuer) Issue(req PatientCredentialRequest, credentialID string, issuedAt, expiresAt time.Time) (*Credential, error) {
	if req.PatientID == "" || req.PatientReference == "" || req.LinkSecretCommitment == "" {
		return nil, errors.New("patient_id, patient_reference, and link_secret_commitment are required")
	}
	if expiresAt.Before(issuedAt) || expiresAt.Equal(issuedAt) {
		return nil, errors.New("expiration must be after issuance")
	}
	if credentialID == "" {
		return nil, errors.New("credential_id is required")
	}

	cred := &Credential{
		CredentialID:   credentialID,
		Type:           []string{"VerifiableCredential", CredentialType},
		Issuer:         i.issuer,
		IssuanceDate:   issuedAt.UTC().Format(time.RFC3339),
		ExpirationDate: expiresAt.UTC().Format(time.RFC3339),
		Schema:         Schema,
		Subject: Subject{
			PatientID: req.PatientID, PatientReference: req.PatientReference,
			DateOfBirth: req.DateOfBirth, EligibilityStatus: req.EligibilityStatus,
			Jurisdiction: req.Jurisdiction, LinkSecretCommitment: req.LinkSecretCommitment,
		},
	}

	msgs := i.messageScalars(cred)
	gens, err := new(bbs.MessageGenerators).Init(i.pk, len(msgs))
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ generators: %w", err)
	}
	sig, err := i.sk.Sign(gens, msgs)
	if err != nil {
		return nil, fmt.Errorf("sign patient credential: %w", err)
	}
	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("serialize BBS+ signature: %w", err)
	}
	pkBytes, err := i.pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("serialize BBS+ public key: %w", err)
	}
	cred.Proof = Proof{
		Type: SignatureType, Cryptosuite: "BLS12-381-SHA256",
		VerificationMethod: i.issuer + "#" + SignatureKeyMethod,
		Created:            issuedAt.UTC().Format(time.RFC3339), ProofPurpose: "assertionMethod",
		MessageOrder: append([]string(nil), MessageOrder...),
		PublicKey:    base64.RawURLEncoding.EncodeToString(pkBytes),
		ProofValue:   base64.RawURLEncoding.EncodeToString(sigBytes),
	}
	return cred, nil
}

func (i *Issuer) Verify(cred *Credential, now time.Time) error {
	if cred == nil {
		return errors.New("credential is nil")
	}
	if len(cred.Proof.MessageOrder) != len(MessageOrder) {
		return errors.New("invalid message order")
	}
	for n := range MessageOrder {
		if cred.Proof.MessageOrder[n] != MessageOrder[n] {
			return errors.New("unexpected message order")
		}
	}
	if cred.Issuer != i.issuer || cred.Schema != Schema {
		return errors.New("issuer or schema mismatch")
	}
	exp, err := time.Parse(time.RFC3339, cred.ExpirationDate)
	if err != nil {
		return fmt.Errorf("invalid expiration: %w", err)
	}
	if !now.Before(exp) {
		return errors.New("credential is expired")
	}
	pkBytes, err := base64.RawURLEncoding.DecodeString(cred.Proof.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}
	pk := new(bbs.PublicKey).Init(i.curve)
	if err = pk.UnmarshalBinary(pkBytes); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("invalid proof encoding: %w", err)
	}
	sig := new(bbs.Signature).Init(i.curve)
	if err = sig.UnmarshalBinary(sigBytes); err != nil {
		return fmt.Errorf("invalid BBS+ signature: %w", err)
	}
	msgs := i.messageScalars(cred)
	gens, err := new(bbs.MessageGenerators).Init(pk, len(msgs))
	if err != nil {
		return err
	}
	if err = pk.Verify(sig, gens, msgs); err != nil {
		return fmt.Errorf("invalid patient credential proof: %w", err)
	}
	return nil
}

// CreatePatientIDProof creates a BBS+ proof of knowledge that reveals only
// patient_id. context binds the proof to a PTA request/session transcript.
func (h *Holder) CreatePatientIDProof(context string, reader io.Reader) (*CredentialProof, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, err
	}
	return h.CreatePatientIDProofForNonce(context, nonce, reader)
}

// CreatePatientIDProofForNonce creates a proof against a nonce supplied by the
// PTA. The nonce must be fresh for each PTA request.
func (h *Holder) CreatePatientIDProofForNonce(context string, nonceBytes []byte, reader io.Reader) (*CredentialProof, error) {
	if h == nil || h.Credential == nil {
		return nil, errors.New("holder credential is missing")
	}
	if len(h.LinkSecret) == 0 {
		return nil, errors.New("holder link secret is missing")
	}
	commitment, err := NewLinkSecretCommitment(h.LinkSecret)
	if err != nil || !EqualCommitment(commitment, h.Credential.Subject.LinkSecretCommitment) {
		return nil, errors.New("holder link secret does not match credential commitment")
	}
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	_, sig, gens, msgs, err := decodeCredentialMaterial(h.Credential, curve)
	if err != nil {
		return nil, err
	}
	proofMsgs := make([]common.ProofMessage, len(msgs))
	for idx, msg := range msgs {
		if idx == 4 {
			proofMsgs[idx] = &common.RevealedMessage{Message: msg}
		} else {
			proofMsgs[idx] = &common.ProofSpecificMessage{Message: msg}
		}
	}
	pok, err := bbs.NewPokSignature(sig, gens, proofMsgs, reader)
	if err != nil {
		return nil, fmt.Errorf("create BBS+ proof: %w", err)
	}
	if len(nonceBytes) == 0 {
		return nil, errors.New("invalid PTA nonce")
	}
	nonce := curve.Scalar.Hash(nonceBytes)
	transcript := merlin.NewTranscript(MessageDomain + ":" + context)
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	if err != nil {
		return nil, err
	}
	pokProof, err := pok.GenerateProof(challenge)
	if err != nil {
		return nil, err
	}
	proofBytes, err := pokProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &CredentialProof{
		Type: "BBS+ProofOfKnowledge-SelectiveDisclosure-v1", CredentialID: h.Credential.CredentialID,
		Revealed:   map[string]string{"patient_id": h.Credential.Subject.PatientID},
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce.Bytes()),
		Challenge:  base64.RawURLEncoding.EncodeToString(challenge.Bytes()),
		ProofValue: base64.RawURLEncoding.EncodeToString(proofBytes),
	}, nil
}

// VerifyPatientIDProof verifies the holder proof without requiring hidden
// credential attributes. It returns the selectively disclosed PatientID.
func (i *Issuer) VerifyPatientIDProof(cred *Credential, proof *CredentialProof, context string) (string, error) {
	if cred == nil || proof == nil {
		return "", errors.New("credential and proof are required")
	}
	if proof.CredentialID != cred.CredentialID {
		return "", errors.New("proof credential mismatch")
	}
	patientID, ok := proof.Revealed["patient_id"]
	if !ok || patientID == "" {
		return "", errors.New("patient_id was not disclosed")
	}
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, _, gens, _, err := decodeCredentialMaterial(cred, curve)
	if err != nil {
		return "", err
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(proof.Nonce)
	if err != nil {
		return "", errors.New("invalid proof nonce")
	}
	nonce, err := curve.Scalar.SetBytes(nonceBytes)
	if err != nil {
		return "", errors.New("invalid proof nonce")
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(proof.Challenge)
	if err != nil {
		return "", errors.New("invalid proof challenge")
	}
	challenge, err := curve.Scalar.SetBytes(challengeBytes)
	if err != nil {
		return "", errors.New("invalid proof challenge")
	}
	proofBytes, err := base64.RawURLEncoding.DecodeString(proof.ProofValue)
	if err != nil {
		return "", errors.New("invalid proof value")
	}
	pok := new(bbs.PokSignatureProof).Init(curve)
	if err = pok.UnmarshalBinary(proofBytes); err != nil {
		return "", fmt.Errorf("invalid proof value: %w", err)
	}
	revealed := map[int]curves.Scalar{4: curve.Scalar.Hash([]byte(MessageDomain + "\x00patient_id\x00" + patientID))}
	transcript := merlin.NewTranscript(MessageDomain + ":" + context)
	if !pok.Verify(revealed, pk, gens, common.Nonce(nonce), common.Challenge(challenge), transcript) {
		return "", errors.New("invalid selective-disclosure proof")
	}
	return patientID, nil
}

func decodeCredentialMaterial(cred *Credential, curve *curves.PairingCurve) (*bbs.PublicKey, *bbs.Signature, *bbs.MessageGenerators, []curves.Scalar, error) {
	pkBytes, err := base64.RawURLEncoding.DecodeString(cred.Proof.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, errors.New("invalid credential public key")
	}
	pk := new(bbs.PublicKey).Init(curve)
	if err = pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, nil, nil, nil, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(cred.Proof.ProofValue)
	if err != nil {
		return nil, nil, nil, nil, errors.New("invalid credential signature")
	}
	sig := new(bbs.Signature).Init(curve)
	if err = sig.UnmarshalBinary(sigBytes); err != nil {
		return nil, nil, nil, nil, err
	}
	values := []string{cred.CredentialID, cred.Issuer, cred.IssuanceDate, cred.ExpirationDate, cred.Subject.PatientID, cred.Subject.PatientReference, cred.Subject.DateOfBirth, cred.Subject.EligibilityStatus, cred.Subject.Jurisdiction, cred.Subject.LinkSecretCommitment}
	msgs := make([]curves.Scalar, len(values))
	for n, value := range values {
		msgs[n] = curve.Scalar.Hash([]byte(MessageDomain + "\x00" + MessageOrder[n] + "\x00" + value))
	}
	gens, err := new(bbs.MessageGenerators).Init(pk, len(msgs))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pk, sig, gens, msgs, nil
}

func (i *Issuer) messageScalars(c *Credential) []curves.Scalar {
	values := []string{c.CredentialID, c.Issuer, c.IssuanceDate, c.ExpirationDate,
		c.Subject.PatientID, c.Subject.PatientReference, c.Subject.DateOfBirth,
		c.Subject.EligibilityStatus, c.Subject.Jurisdiction, c.Subject.LinkSecretCommitment}
	result := make([]curves.Scalar, len(values))
	for n, value := range values {
		result[n] = i.curve.Scalar.Hash([]byte(MessageDomain + "\x00" + MessageOrder[n] + "\x00" + value))
	}
	return result
}

func NewLinkSecretCommitment(secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("link secret must not be empty")
	}
	h := sha256.New()
	h.Write([]byte("HIDM-LINK-SECRET-COMMITMENT-v1\x00"))
	h.Write(secret)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func NewRandomLinkSecret() ([]byte, error) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	return secret, err
}

func EqualCommitment(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (c Credential) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
