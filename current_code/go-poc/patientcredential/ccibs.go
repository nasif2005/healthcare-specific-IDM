package patientcredential

// Research POC implementation of the Cha--Cheon identity-based signature
// construction over BLS12-381. It uses CIRCL's maintained pairing primitives;
// its encoding and domain-separation strings are Go-native and therefore are
// not wire-compatible with the separate MIRACL Java reference implementation.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/cloudflare/circl/ecc/bls12381"
)

const ccIBSIdentityDST = "HIDM-CCIBS-BLS12381-G1-v1"

type CCIBSAuthority struct {
	secret *bls12381.Scalar
	public []byte
}

// NewCCIBSAuthority creates the APC's master secret and public key.
func NewCCIBSAuthority(reader io.Reader) (*CCIBSAuthority, error) {
	if reader == nil {
		reader = rand.Reader
	}
	s := new(bls12381.Scalar)
	if err := s.Random(reader); err != nil {
		return nil, err
	}
	pub := new(bls12381.G2)
	pub.ScalarMult(s, bls12381.G2Generator())
	return &CCIBSAuthority{secret: s, public: pub.BytesCompressed()}, nil
}

func (a *CCIBSAuthority) MasterPublicKey() []byte { return append([]byte(nil), a.public...) }

// Extract derives the patient-held private key bound to a pseudonym identity.
func (a *CCIBSAuthority) Extract(pseudonym string) ([]byte, error) {
	if a == nil || a.secret == nil || pseudonym == "" {
		return nil, errors.New("CC-IBS authority or pseudonym is invalid")
	}
	key := new(bls12381.G1)
	key.ScalarMult(a.secret, ccIBSHashIdentity(pseudonym))
	return key.BytesCompressed(), nil
}

// Sign creates a two-point CC-IBS signature (U,V) for a booking transcript.
func CCIBSSign(pseudonym string, privateKey, message []byte, reader io.Reader) (string, error) {
	if pseudonym == "" || len(privateKey) == 0 || len(message) == 0 {
		return "", errors.New("CC-IBS signing inputs are incomplete")
	}
	if reader == nil {
		reader = rand.Reader
	}
	ssk := new(bls12381.G1)
	if err := ssk.SetBytes(privateKey); err != nil || ssk.IsIdentity() {
		return "", errors.New("invalid CC-IBS private key")
	}
	r := new(bls12381.Scalar)
	if err := r.Random(reader); err != nil {
		return "", err
	}
	u := new(bls12381.G1)
	u.ScalarMult(r, ccIBSHashIdentity(pseudonym))
	h := ccIBSMessageScalar(message, u.BytesCompressed())
	r.Add(r, h)
	v := new(bls12381.G1)
	v.ScalarMult(r, ssk)
	return base64.RawURLEncoding.EncodeToString(u.BytesCompressed()) + "." + base64.RawURLEncoding.EncodeToString(v.BytesCompressed()), nil
}

// CCIBSVerifier verifies signatures using the APC master public key.
type CCIBSVerifier struct{ MasterPublicKey []byte }

func (v CCIBSVerifier) VerifyPseudonymSignature(pseudonym string, message []byte, signature string) error {
	if pseudonym == "" || len(message) == 0 || len(v.MasterPublicKey) == 0 {
		return errors.New("CC-IBS verification inputs are incomplete")
	}
	parts := strings.Split(signature, ".")
	if len(parts) != 2 {
		return errors.New("invalid CC-IBS signature encoding")
	}
	ub, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid CC-IBS signature U")
	}
	vb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid CC-IBS signature V")
	}
	u, vv, mpk := new(bls12381.G1), new(bls12381.G1), new(bls12381.G2)
	if u.SetBytes(ub) != nil || vv.SetBytes(vb) != nil || mpk.SetBytes(v.MasterPublicKey) != nil || u.IsIdentity() || vv.IsIdentity() || mpk.IsIdentity() {
		return errors.New("invalid CC-IBS group element")
	}
	h := ccIBSMessageScalar(message, ub)
	hq := new(bls12381.G1)
	hq.ScalarMult(h, ccIBSHashIdentity(pseudonym))
	u.Add(u, hq)
	vv.Neg()
	if !bls12381.ProdPairFrac([]*bls12381.G1{vv, u}, []*bls12381.G2{bls12381.G2Generator(), mpk}, []int{1, 1}).IsIdentity() {
		return errors.New("invalid CC-IBS signature")
	}
	return nil
}

func ccIBSHashIdentity(identity string) *bls12381.G1 {
	q := new(bls12381.G1)
	q.Hash([]byte(identity), []byte(ccIBSIdentityDST))
	return q
}
func ccIBSMessageScalar(message, u []byte) *bls12381.Scalar {
	h := sha256.New()
	h.Write([]byte("HIDM-CCIBS-MESSAGE-v1\x00"))
	h.Write(message)
	h.Write(u)
	sum := h.Sum(nil)
	s := new(bls12381.Scalar)
	s.SetBytes(sum)
	return s
}
