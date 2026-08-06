package patientcredential

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

const PseudonymTokenType = "HIDMPseudonymToken-v1"

// PseudonymTokenRequest is sent by the patient after generating a fresh
// pseudonym. PatientID is intentionally absent: it is obtained from the
// verified credential proof and is never placed in the token.
type PseudonymTokenRequest struct {
	Pseudonym    string    `json:"pseudonym"`
	BindingProof string    `json:"binding_proof"`
	CredentialID string    `json:"credential_id"`
	Audience     string    `json:"audience"`
	PolicyID     string    `json:"policy_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type PseudonymToken struct {
	Type               string `json:"type"`
	TokenID            string `json:"token_id"`
	Pseudonym          string `json:"pseudonym"`
	CredentialID       string `json:"credential_id"`
	Audience           string `json:"audience"`
	PolicyID           string `json:"policy_id"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	VerificationMethod string `json:"verification_method"`
	PublicKey          string `json:"public_key"`
	Signature          string `json:"signature"`
}

type tokenPayload struct {
	Domain, Type, TokenID, Pseudonym, CredentialID, Audience, PolicyID, IssuedAt, ExpiresAt string
}

// PTAService combines the PTA proof verifier with its token-signing key. Its
// trace map is an in-memory POC representation of the APC/PTA conditional-
// traceability store and must be replaced by protected shared storage.
type PTAService struct {
	*PTA
	suite  *edwards25519.SuiteEd25519
	secret kyber.Scalar
	public kyber.Point
	trace  map[string]string
}

func NewPTAService(apcVerifier *Issuer, reader io.Reader) (*PTAService, error) {
	_ = reader // Kyber's scalar sampler consumes its cipher.Stream internally.
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().Pick(suite.RandomStream())
	return &PTAService{
		PTA: NewPTA(apcVerifier), suite: suite, secret: secret,
		public: suite.Point().Mul(secret, nil), trace: make(map[string]string),
	}, nil
}

func (p *PTAService) PublicKeyBytes() ([]byte, error) { return p.public.MarshalBinary() }

// IssuePseudonymToken verifies the patient proof and then signs the token.
// The patientID returned by proof verification is stored only in the PTA
// trace map; it is not serialized into the token.
func (p *PTAService) IssuePseudonymToken(cred *Credential, proof *CredentialProof, nonce []byte, context string, req PseudonymTokenRequest, now time.Time, tokenID string) (*PseudonymToken, error) {
	if p == nil || p.PTA == nil {
		return nil, errors.New("PTA service is not configured")
	}
	if req.Pseudonym == "" || req.BindingProof == "" || req.CredentialID == "" || req.Audience == "" || tokenID == "" {
		return nil, errors.New("pseudonym, binding_proof, credential_id, audience, and token_id are required")
	}
	if req.CredentialID != cred.CredentialID {
		return nil, errors.New("token request credential mismatch")
	}
	if !req.ExpiresAt.After(now) {
		return nil, errors.New("token expiration must be in the future")
	}
	patientID, err := p.PTA.VerifyPatientIDProof(cred, proof, context, nonce)
	if err != nil {
		return nil, fmt.Errorf("verify patient credential proof: %w", err)
	}
	if err := VerifyPseudonymBinding(req.Pseudonym, req.BindingProof, patientID, req.CredentialID, req.Audience, req.PolicyID, nonce); err != nil {
		return nil, err
	}
	token := &PseudonymToken{Type: PseudonymTokenType, TokenID: tokenID, Pseudonym: req.Pseudonym, CredentialID: req.CredentialID, Audience: req.Audience, PolicyID: req.PolicyID, IssuedAt: now.UTC().Format(time.RFC3339), ExpiresAt: req.ExpiresAt.UTC().Format(time.RFC3339), VerificationMethod: "pta-schnorr-key-1"}
	keyBytes, err := p.public.MarshalBinary()
	if err != nil {
		return nil, err
	}
	token.PublicKey = base64.RawURLEncoding.EncodeToString(keyBytes)
	sig, err := schnorr.Sign(p.suite, p.secret, tokenBytes(token))
	if err != nil {
		return nil, fmt.Errorf("sign pseudonym token: %w", err)
	}
	token.Signature = base64.RawURLEncoding.EncodeToString(sig)
	p.trace[token.Pseudonym] = patientID
	return token, nil
}

func VerifyPseudonymToken(token *PseudonymToken, now time.Time, audience string) error {
	if token == nil || token.Type != PseudonymTokenType {
		return errors.New("invalid pseudonym token")
	}
	if audience != "" && token.Audience != audience {
		return errors.New("token audience mismatch")
	}
	exp, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return errors.New("invalid token expiration")
	}
	if !now.Before(exp) {
		return errors.New("pseudonym token is expired")
	}
	pkBytes, err := base64.RawURLEncoding.DecodeString(token.PublicKey)
	if err != nil {
		return errors.New("invalid token public key")
	}
	pk := edwards25519.NewBlakeSHA256Ed25519().Point()
	if err = pk.UnmarshalBinary(pkBytes); err != nil {
		return errors.New("invalid token public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return errors.New("invalid token signature")
	}
	if err = schnorr.Verify(edwards25519.NewBlakeSHA256Ed25519(), pk, tokenBytes(token), sig); err != nil {
		return fmt.Errorf("invalid pseudonym token signature: %w", err)
	}
	return nil
}

// TracePseudonym is an authorized-tracing POC hook. Authorization, threshold
// approval, and audit logging must be added before deployment.
func (p *PTAService) TracePseudonym(pseudonym string) (string, bool) {
	patientID, ok := p.trace[pseudonym]
	return patientID, ok
}

func tokenBytes(token *PseudonymToken) []byte {
	data, _ := json.Marshal(tokenPayload{"HIDM-PSEUDONYM-TOKEN-v1", token.Type, token.TokenID, token.Pseudonym, token.CredentialID, token.Audience, token.PolicyID, token.IssuedAt, token.ExpiresAt})
	return data
}
