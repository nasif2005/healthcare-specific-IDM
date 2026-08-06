package patientcredential

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

const AppointmentTokenType = "HIDMAppointmentToken-v1"

// AppointmentTokenCommonInfo is public information that the APC deliberately
// binds to the partially blind signature. It intentionally contains no
// provider identifier, PatientID, pseudonym, or ATI.
type AppointmentTokenCommonInfo struct {
	Version   string `json:"version"`
	TokenType string `json:"token_type"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type AppointmentToken struct {
	Type               string                     `json:"type"`
	ATI                string                     `json:"ati"`
	CommonInfo         AppointmentTokenCommonInfo `json:"common_info"`
	VerificationMethod string                     `json:"verification_method"`
	PublicKey          string                     `json:"public_key"`
	SignatureR         string                     `json:"signature_r"`
	SignatureS         string                     `json:"signature_s"`
}

// AppointmentTokenChallenge is sent from the APC to the patient only after a
// valid credential presentation. Commitment is the blind-signature nonce R.
type AppointmentTokenChallenge struct {
	SessionID          string                     `json:"session_id"`
	CommonInfo         AppointmentTokenCommonInfo `json:"common_info"`
	Commitment         string                     `json:"commitment"`
	AuthorityPublicKey string                     `json:"authority_public_key"`
}

type AppointmentTokenBlindRequest struct {
	SessionID        string `json:"session_id"`
	BlindedChallenge string `json:"blinded_challenge"`
}

type AppointmentTokenBlindResponse struct {
	SessionID string `json:"session_id"`
	Response  string `json:"response"`
}

// AppointmentTokenBlindingState remains only in the patient's memory until
// the signature is finalized. It must not be sent to the APC.
type AppointmentTokenBlindingState struct {
	ati        string
	commonInfo AppointmentTokenCommonInfo
	rPrime     kyber.Point
	alpha      kyber.Scalar
}

type appointmentTokenSession struct {
	nonce      kyber.Scalar
	commonInfo AppointmentTokenCommonInfo
	used       bool
}

// AppointmentTokenAuthority is the APC role for partially blind Schnorr
// issuance. It verifies a credential presentation but never receives ATI.
type AppointmentTokenAuthority struct {
	credentialVerifier *PTA
	suite              *edwards25519.SuiteEd25519
	secret             kyber.Scalar
	public             kyber.Point
	sessions           map[string]*appointmentTokenSession
	mu                 sync.Mutex
}

// AppointmentTokenUsageLedger is the healthcare-provider-side, one-time-use
// check for this POC. It receives an ATI only when the patient spends the
// token; it has no communication path to the APC. Deployments must replace
// this in-memory ledger with an atomic, durable provider-side spent-token
// registry.
type AppointmentTokenUsageLedger struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewAppointmentTokenUsageLedger() *AppointmentTokenUsageLedger {
	return &AppointmentTokenUsageLedger{used: make(map[string]struct{})}
}

func (l *AppointmentTokenUsageLedger) Consume(token *AppointmentToken, now time.Time) error {
	if l == nil {
		return errors.New("appointment token usage ledger is nil")
	}
	if err := VerifyAppointmentToken(token, now); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.used[token.ATI]; exists {
		return errors.New("appointment token has already been used")
	}
	l.used[token.ATI] = struct{}{}
	return nil
}

func NewAppointmentTokenAuthority(apcVerifier *Issuer) (*AppointmentTokenAuthority, error) {
	if apcVerifier == nil {
		return nil, errors.New("APC credential verifier is required")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().Pick(suite.RandomStream())
	return &AppointmentTokenAuthority{
		credentialVerifier: NewPTA(apcVerifier), suite: suite, secret: secret,
		public: suite.Point().Mul(secret, nil), sessions: make(map[string]*appointmentTokenSession),
	}, nil
}

func (a *AppointmentTokenAuthority) NewCredentialChallenge(reader io.Reader) ([]byte, error) {
	if a == nil || a.credentialVerifier == nil {
		return nil, errors.New("appointment token authority is not configured")
	}
	return a.credentialVerifier.NewChallenge(reader)
}

// BeginIssuance authenticates the patient to the APC and returns an APC
// commitment for blind signing. The returned challenge contains no ATI.
func (a *AppointmentTokenAuthority) BeginIssuance(cred *Credential, proof *CredentialProof, credentialNonce []byte, context string, now, expiresAt time.Time, reader io.Reader) (*AppointmentTokenChallenge, error) {
	if a == nil || a.credentialVerifier == nil {
		return nil, errors.New("appointment token authority is not configured")
	}
	if !expiresAt.After(now) {
		return nil, errors.New("appointment token expiration must be in the future")
	}
	if _, err := a.credentialVerifier.VerifyPatientIDProof(cred, proof, context, credentialNonce); err != nil {
		return nil, fmt.Errorf("verify patient credential proof: %w", err)
	}
	sessionID, err := randomAppointmentSessionID(reader)
	if err != nil {
		return nil, err
	}
	common := AppointmentTokenCommonInfo{Version: "HIDM-AT-COMMON-v1", TokenType: AppointmentTokenType, IssuedAt: now.UTC().Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339)}
	nonce := a.suite.Scalar().Pick(a.suite.RandomStream())
	commitment := a.suite.Point().Mul(nonce, nil)
	a.mu.Lock()
	a.sessions[sessionID] = &appointmentTokenSession{nonce: nonce, commonInfo: common}
	a.mu.Unlock()
	commitmentBytes, err := commitment.MarshalBinary()
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err := a.public.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &AppointmentTokenChallenge{SessionID: sessionID, CommonInfo: common, Commitment: base64.RawURLEncoding.EncodeToString(commitmentBytes), AuthorityPublicKey: base64.RawURLEncoding.EncodeToString(publicKeyBytes)}, nil
}

// PrepareBlindAppointmentToken blinds patient-generated ATI. The resulting
// request reveals only the blinded Schnorr challenge to the APC.
func PrepareBlindAppointmentToken(challenge *AppointmentTokenChallenge, ati string) (*AppointmentTokenBlindRequest, *AppointmentTokenBlindingState, error) {
	if challenge == nil || challenge.SessionID == "" || ati == "" || challenge.CommonInfo.TokenType != AppointmentTokenType {
		return nil, nil, errors.New("invalid appointment token challenge")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rBytes, err := base64.RawURLEncoding.DecodeString(challenge.Commitment)
	if err != nil {
		return nil, nil, errors.New("invalid APC commitment")
	}
	r := suite.Point()
	if err = r.UnmarshalBinary(rBytes); err != nil {
		return nil, nil, errors.New("invalid APC commitment")
	}
	alpha := suite.Scalar().Pick(suite.RandomStream())
	beta := suite.Scalar().Pick(suite.RandomStream())
	publicBytes, err := base64.RawURLEncoding.DecodeString(challenge.AuthorityPublicKey)
	if err != nil {
		return nil, nil, errors.New("invalid appointment authority public key")
	}
	basePublic := suite.Point()
	if err = basePublic.UnmarshalBinary(publicBytes); err != nil {
		return nil, nil, errors.New("invalid appointment authority public key")
	}
	public := appointmentContextPublic(suite, basePublic, challenge.CommonInfo)
	rPrime := suite.Point().Add(r, suite.Point().Mul(alpha, nil))
	rPrime.Add(rPrime, suite.Point().Mul(beta, public))
	e := appointmentChallengeScalar(suite, ati, challenge.CommonInfo, rPrime)
	ePrime := suite.Scalar().Add(e, beta)
	eBytes, err := ePrime.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return &AppointmentTokenBlindRequest{SessionID: challenge.SessionID, BlindedChallenge: base64.RawURLEncoding.EncodeToString(eBytes)}, &AppointmentTokenBlindingState{ati: ati, commonInfo: challenge.CommonInfo, rPrime: rPrime, alpha: alpha}, nil
}

// SignBlindAppointmentToken signs a blinded challenge. ATI is never an input
// to this method and is therefore unavailable to the APC.
func (a *AppointmentTokenAuthority) SignBlindAppointmentToken(request *AppointmentTokenBlindRequest) (*AppointmentTokenBlindResponse, error) {
	if a == nil || request == nil || request.SessionID == "" {
		return nil, errors.New("invalid blind appointment token request")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[request.SessionID]
	if !ok || session.used {
		return nil, errors.New("appointment token session is invalid or already used")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(request.BlindedChallenge)
	if err != nil {
		return nil, errors.New("invalid blinded challenge")
	}
	ePrime := a.suite.Scalar()
	if err = ePrime.UnmarshalBinary(eBytes); err != nil {
		return nil, errors.New("invalid blinded challenge")
	}
	contextSecret := appointmentContextSecret(a.suite, a.secret, session.commonInfo)
	response := a.suite.Scalar().Add(session.nonce, a.suite.Scalar().Mul(ePrime, contextSecret))
	responseBytes, err := response.MarshalBinary()
	if err != nil {
		return nil, err
	}
	session.used = true
	return &AppointmentTokenBlindResponse{SessionID: request.SessionID, Response: base64.RawURLEncoding.EncodeToString(responseBytes)}, nil
}

func FinalizeAppointmentToken(challenge *AppointmentTokenChallenge, state *AppointmentTokenBlindingState, response *AppointmentTokenBlindResponse, authorityPublic kyber.Point) (*AppointmentToken, error) {
	if challenge == nil || state == nil || response == nil || challenge.SessionID == "" || challenge.SessionID != response.SessionID || authorityPublic == nil {
		return nil, errors.New("invalid appointment token finalization inputs")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	challengePublicBytes, err := base64.RawURLEncoding.DecodeString(challenge.AuthorityPublicKey)
	if err != nil {
		return nil, errors.New("invalid appointment authority public key")
	}
	providedPublicBytes, err := authorityPublic.MarshalBinary()
	if err != nil || !bytes.Equal(challengePublicBytes, providedPublicBytes) {
		return nil, errors.New("appointment authority public key does not match the challenge")
	}
	sBytes, err := base64.RawURLEncoding.DecodeString(response.Response)
	if err != nil {
		return nil, errors.New("invalid blind appointment token response")
	}
	s := suite.Scalar()
	if err = s.UnmarshalBinary(sBytes); err != nil {
		return nil, errors.New("invalid blind appointment token response")
	}
	s.Add(s, state.alpha)
	rBytes, err := state.rPrime.MarshalBinary()
	if err != nil {
		return nil, err
	}
	finalS, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	token := &AppointmentToken{Type: AppointmentTokenType, ATI: state.ati, CommonInfo: state.commonInfo, VerificationMethod: "apc-partially-blind-schnorr-key-1", PublicKey: base64.RawURLEncoding.EncodeToString(providedPublicBytes), SignatureR: base64.RawURLEncoding.EncodeToString(rBytes), SignatureS: base64.RawURLEncoding.EncodeToString(finalS)}
	if err = verifyAppointmentTokenSignature(token); err != nil {
		return nil, fmt.Errorf("APC returned an invalid blind signature: %w", err)
	}
	return token, nil
}

func VerifyAppointmentToken(token *AppointmentToken, now time.Time) error {
	if token == nil || token.Type != AppointmentTokenType || token.ATI == "" || token.CommonInfo.Version != "HIDM-AT-COMMON-v1" || token.CommonInfo.TokenType != AppointmentTokenType {
		return errors.New("invalid appointment token")
	}
	expiresAt, err := time.Parse(time.RFC3339, token.CommonInfo.ExpiresAt)
	if err != nil || !now.Before(expiresAt) {
		return errors.New("appointment token is expired")
	}
	return verifyAppointmentTokenSignature(token)
}

func verifyAppointmentTokenSignature(token *AppointmentToken) error {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	pkBytes, err := base64.RawURLEncoding.DecodeString(token.PublicKey)
	if err != nil {
		return errors.New("invalid appointment authority public key")
	}
	public := suite.Point()
	if err = public.UnmarshalBinary(pkBytes); err != nil {
		return errors.New("invalid appointment authority public key")
	}
	rBytes, err := base64.RawURLEncoding.DecodeString(token.SignatureR)
	if err != nil {
		return errors.New("invalid appointment token signature")
	}
	r := suite.Point()
	if err = r.UnmarshalBinary(rBytes); err != nil {
		return errors.New("invalid appointment token signature")
	}
	sBytes, err := base64.RawURLEncoding.DecodeString(token.SignatureS)
	if err != nil {
		return errors.New("invalid appointment token signature")
	}
	s := suite.Scalar()
	if err = s.UnmarshalBinary(sBytes); err != nil {
		return errors.New("invalid appointment token signature")
	}
	contextPublic := appointmentContextPublic(suite, public, token.CommonInfo)
	if contextPublic == nil {
		return errors.New("invalid appointment token common information")
	}
	e := appointmentChallengeScalar(suite, token.ATI, token.CommonInfo, r)
	left := suite.Point().Mul(s, nil)
	right := suite.Point().Add(r, suite.Point().Mul(e, contextPublic))
	if !left.Equal(right) {
		return errors.New("invalid appointment token signature")
	}
	return nil
}

func (a *AppointmentTokenAuthority) PublicKey() kyber.Point { return a.public }

func NewAppointmentTokenID(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func randomAppointmentSessionID(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", err
	}
	return "ats_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func appointmentCommonInfoBytes(common AppointmentTokenCommonInfo) []byte {
	b, _ := json.Marshal(common)
	return b
}
func appointmentHashScalar(suite *edwards25519.SuiteEd25519, parts ...[]byte) kyber.Scalar {
	h := sha256.New()
	for _, part := range parts {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	return suite.Scalar().SetBytes(h.Sum(nil))
}
func appointmentContextScalar(suite *edwards25519.SuiteEd25519, common AppointmentTokenCommonInfo) kyber.Scalar {
	return appointmentHashScalar(suite, []byte("HIDM-AT-CONTEXT-v1"), appointmentCommonInfoBytes(common))
}
func appointmentContextSecret(suite *edwards25519.SuiteEd25519, secret kyber.Scalar, common AppointmentTokenCommonInfo) kyber.Scalar {
	return suite.Scalar().Add(secret, appointmentContextScalar(suite, common))
}
func appointmentContextPublic(suite *edwards25519.SuiteEd25519, public kyber.Point, common AppointmentTokenCommonInfo) kyber.Point {
	if public == nil {
		return nil
	}
	return suite.Point().Add(public, suite.Point().Mul(appointmentContextScalar(suite, common), nil))
}
func appointmentChallengeScalar(suite *edwards25519.SuiteEd25519, ati string, common AppointmentTokenCommonInfo, r kyber.Point) kyber.Scalar {
	rBytes, _ := r.MarshalBinary()
	return appointmentHashScalar(suite, []byte("HIDM-AT-BLIND-SCHNORR-v1"), []byte(ati), appointmentCommonInfoBytes(common), rBytes)
}
