package patientcredential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

const (
	prePseudonymScheme = "HIDM-AFGH05-PRE-BLS12381-v1"
	pbpScheme          = "HIDM-PBP-FS-BLS12381-v1"
)

// PREPseudonym is the canonical serialization of (P1, P2) together with the
// pseudonym-generation public key required to verify the PBP. P1 is in GT and
// P2 and PublicKey are in G2, matching the equations in the paper.
type PREPseudonym struct {
	Version   string `json:"version"`
	Scheme    string `json:"scheme"`
	P1        string `json:"p1_gt"`
	P2        string `json:"p2_g2"`
	PublicKey string `json:"pseudonym_generation_public_key_g2"`
}

// PseudonymBindingProof is the Fiat--Shamir proof pi_PBP=(T1,T2,s).
type PseudonymBindingProof struct {
	Version string `json:"version"`
	Scheme  string `json:"scheme"`
	T1      string `json:"t1_gt"`
	T2      string `json:"t2_g2"`
	S       string `json:"s"`
}

// NewPseudonym creates the pairing-based PRE pseudonym (P1,P2) and its
// session-bound Fiat--Shamir PBP. PatientID is not serialized in either value.
func NewPseudonym(patientID, credentialID, audience, policyID string, ptaNonce []byte, reader io.Reader) (string, string, error) {
	if patientID == "" || credentialID == "" || audience == "" || len(ptaNonce) == 0 {
		return "", "", errors.New("patient ID, credential ID, audience, and PTA nonce are required")
	}
	if reader == nil {
		return "", "", errors.New("randomness source is required")
	}
	x, err := randomScalar(reader)
	if err != nil {
		return "", "", err
	}
	r, err := randomScalar(reader)
	if err != nil {
		return "", "", err
	}
	pk := new(bls.G2)
	pk.ScalarMult(x, bls.G2Generator())
	z := bls.Pair(bls.G1Generator(), bls.G2Generator())
	h := hashToScalar([]byte("HIDM-PRE-PATIENTID-v1"), []byte(patientID))
	zToR, zToH := new(bls.Gt), new(bls.Gt)
	zToR.Exp(z, r)
	zToH.Exp(z, h)
	p1 := new(bls.Gt)
	p1.Mul(zToR, zToH)
	p2 := new(bls.G2)
	p2.ScalarMult(r, pk)

	pseudonym := PREPseudonym{Version: "1", Scheme: prePseudonymScheme, P1: encodeGT(p1), P2: encodeG2(p2), PublicKey: encodeG2(pk)}
	pseudonymJSON, err := json.Marshal(pseudonym)
	if err != nil {
		return "", "", err
	}
	encoded := "pyn_" + base64.RawURLEncoding.EncodeToString(pseudonymJSON)

	t, err := randomScalar(reader)
	if err != nil {
		return "", "", err
	}
	t1 := new(bls.Gt)
	t1.Exp(z, t)
	t2 := new(bls.G2)
	t2.ScalarMult(t, pk)
	c := pbpChallenge(encoded, credentialID, audience, policyID, ptaNonce, t1, t2)
	cr := new(bls.Scalar)
	cr.Mul(c, r)
	s := new(bls.Scalar)
	s.Add(t, cr)
	pbp := PseudonymBindingProof{Version: "1", Scheme: pbpScheme, T1: encodeGT(t1), T2: encodeG2(t2), S: encodeScalar(s)}
	pbpJSON, err := json.Marshal(pbp)
	if err != nil {
		return "", "", err
	}
	return encoded, "pbp_" + base64.RawURLEncoding.EncodeToString(pbpJSON), nil
}

// VerifyPseudonymBinding verifies the PBP against the PatientID obtained from
// the verified BBS+ credential presentation and the one-time PTA challenge.
func VerifyPseudonymBinding(encoded, encodedProof, patientID, credentialID, audience, policyID string, ptaNonce []byte) error {
	if patientID == "" || credentialID == "" || audience == "" || len(ptaNonce) == 0 {
		return errors.New("patient ID, credential ID, audience, and PTA nonce are required")
	}
	p, err := decodePseudonym(encoded)
	if err != nil {
		return err
	}
	proof, err := decodePBP(encodedProof)
	if err != nil {
		return err
	}
	p1, err := decodeGT(p.P1)
	if err != nil || p1.IsIdentity() {
		return errors.New("invalid pseudonym P1")
	}
	p2, err := decodeG2(p.P2)
	if err != nil || isG2Identity(p2) {
		return errors.New("invalid pseudonym P2")
	}
	pk, err := decodeG2(p.PublicKey)
	if err != nil || isG2Identity(pk) {
		return errors.New("invalid pseudonym public key")
	}
	t1, err := decodeGT(proof.T1)
	if err != nil || t1.IsIdentity() {
		return errors.New("invalid PBP T1")
	}
	t2, err := decodeG2(proof.T2)
	if err != nil || isG2Identity(t2) {
		return errors.New("invalid PBP T2")
	}
	s, err := decodeScalar(proof.S)
	if err != nil {
		return errors.New("invalid PBP response")
	}
	h := hashToScalar([]byte("HIDM-PRE-PATIENTID-v1"), []byte(patientID))
	z := bls.Pair(bls.G1Generator(), bls.G2Generator())
	zToH := new(bls.Gt)
	zToH.Exp(z, h)
	zToH.Inv(zToH)
	p1OverZToH := new(bls.Gt)
	p1OverZToH.Mul(p1, zToH)
	c := pbpChallenge(encoded, credentialID, audience, policyID, ptaNonce, t1, t2)

	left1 := new(bls.Gt)
	left1.Exp(z, s)
	rightTerm := new(bls.Gt)
	rightTerm.Exp(p1OverZToH, c)
	right1 := new(bls.Gt)
	right1.Mul(t1, rightTerm)
	if !left1.IsEqual(right1) {
		return errors.New("PBP GT equation failed")
	}
	left2 := new(bls.G2)
	left2.ScalarMult(s, pk)
	cp2 := new(bls.G2)
	cp2.ScalarMult(c, p2)
	right2 := new(bls.G2)
	right2.Add(t2, cp2)
	if !left2.IsEqual(right2) {
		return errors.New("PBP G2 equation failed")
	}
	return nil
}

func decodePseudonym(encoded string) (*PREPseudonym, error) {
	if len(encoded) < 5 || encoded[:4] != "pyn_" {
		return nil, errors.New("invalid pseudonym format")
	}
	b, err := base64.RawURLEncoding.DecodeString(encoded[4:])
	if err != nil {
		return nil, errors.New("invalid pseudonym encoding")
	}
	var p PREPseudonym
	if err := json.Unmarshal(b, &p); err != nil || p.Version != "1" || p.Scheme != prePseudonymScheme {
		return nil, errors.New("invalid PRE pseudonym")
	}
	return &p, nil
}

func decodePBP(encoded string) (*PseudonymBindingProof, error) {
	if len(encoded) < 5 || encoded[:4] != "pbp_" {
		return nil, errors.New("invalid PBP format")
	}
	b, err := base64.RawURLEncoding.DecodeString(encoded[4:])
	if err != nil {
		return nil, errors.New("invalid PBP encoding")
	}
	var p PseudonymBindingProof
	if err := json.Unmarshal(b, &p); err != nil || p.Version != "1" || p.Scheme != pbpScheme {
		return nil, errors.New("invalid PBP")
	}
	return &p, nil
}

func pbpChallenge(pseudonym, credentialID, audience, policyID string, nonce []byte, t1 *bls.Gt, t2 *bls.G2) *bls.Scalar {
	return hashToScalar(
		[]byte("HIDM-PBP-v1"), []byte(prePseudonymScheme), []byte(credentialID), nonce,
		[]byte(audience), []byte(policyID), []byte(pseudonym), gtBytes(t1), t2.BytesCompressed(),
	)
}

func hashToScalar(parts ...[]byte) *bls.Scalar {
	h := sha256.New()
	for _, part := range parts {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	s := new(bls.Scalar)
	s.SetBytes(h.Sum(nil))
	return s
}

func randomScalar(reader io.Reader) (*bls.Scalar, error) {
	for range 16 {
		s := new(bls.Scalar)
		if err := s.Random(reader); err != nil {
			return nil, err
		}
		if !isScalarZero(s) {
			return s, nil
		}
	}
	return nil, errors.New("failed to sample non-zero scalar")
}

func gtBytes(v *bls.Gt) []byte  { b, _ := v.MarshalBinary(); return b }
func encodeGT(v *bls.Gt) string { return base64.RawURLEncoding.EncodeToString(gtBytes(v)) }
func encodeG2(v *bls.G2) string { return base64.RawURLEncoding.EncodeToString(v.BytesCompressed()) }
func encodeScalar(v *bls.Scalar) string {
	b, _ := v.MarshalBinary()
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeGT(encoded string) (*bls.Gt, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	v := new(bls.Gt)
	return v, v.UnmarshalBinary(b)
}
func decodeG2(encoded string) (*bls.G2, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	v := new(bls.G2)
	return v, v.SetBytes(b)
}
func decodeScalar(encoded string) (*bls.Scalar, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	v := new(bls.Scalar)
	v.SetBytes(b)
	return v, nil
}
func isG2Identity(v *bls.G2) bool {
	identity := new(bls.G2)
	identity.SetIdentity()
	return v.IsEqual(identity)
}

func isScalarZero(v *bls.Scalar) bool {
	b, _ := v.MarshalBinary()
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}
