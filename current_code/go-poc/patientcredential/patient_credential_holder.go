package patientcredential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// HolderSecretEnvelope is the on-disk representation of the patient's
// holder secret. The secret is encrypted; it is never written as plaintext.
type HolderSecretEnvelope struct {
	Version      int    `json:"version"`
	CredentialID string `json:"credential_id"`
	Cipher       string `json:"cipher"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// PseudonymPrivateKey is patient-held Cha--Cheon IBS key material. The raw
// PrivateKey bytes are never serialized directly; SavePseudonymPrivateKey
// encrypts them under the wallet key.
type PseudonymPrivateKey struct {
	KeyID                 string
	PseudonymID           string
	APCVerificationMethod string
	CreatedAt             string
	PrivateKey            []byte
}

// PseudonymPrivateKeyEnvelope is the encrypted on-disk representation of a
// pseudonym-specific private key. Public metadata is authenticated as AES-GCM
// additional data so it cannot be modified without detection.
type PseudonymPrivateKeyEnvelope struct {
	Version               int    `json:"version"`
	KeyType               string `json:"key_type"`
	KeyID                 string `json:"key_id"`
	PseudonymID           string `json:"pseudonym_id"`
	APCVerificationMethod string `json:"apc_verification_method"`
	CreatedAt             string `json:"created_at"`
	Cipher                string `json:"cipher"`
	Nonce                 string `json:"nonce"`
	Ciphertext            string `json:"ciphertext"`
}

// SavePatientCredential stores the public credential as JSON. This file may
// be copied to a verifier when the complete credential is explicitly needed;
// normal selective disclosure sends only a CredentialProof.
func SavePatientCredential(path string, credential *Credential) error {
	if credential == nil {
		return errors.New("credential is nil")
	}
	data, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadPatientCredential(path string) (*Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var credential Credential
	if err = json.Unmarshal(data, &credential); err != nil {
		return nil, fmt.Errorf("decode patient credential: %w", err)
	}
	return &credential, nil
}

// SaveHolderSecret stores the patient-side link secret encrypted under a
// caller-provided 32-byte wallet key. In production, obtain walletKey from an
// OS secure store, KMS, or hardware-backed walletâ€”not from a JSON file.
func SaveHolderSecret(path, credentialID string, secret, walletKey []byte) error {
	if len(secret) == 0 {
		return errors.New("holder secret is empty")
	}
	aead, err := newWalletAEAD(walletKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, secret, []byte(credentialID))
	envelope := HolderSecretEnvelope{Version: 1, CredentialID: credentialID, Cipher: "AES-256-GCM", Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(sealed)}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadHolderSecret(path, credentialID string, walletKey []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope HolderSecretEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode holder secret envelope: %w", err)
	}
	if envelope.Version != 1 || envelope.CredentialID != credentialID || envelope.Cipher != "AES-256-GCM" {
		return nil, errors.New("invalid holder secret envelope")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, errors.New("invalid holder secret nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid holder secret ciphertext")
	}
	aead, err := newWalletAEAD(walletKey)
	if err != nil {
		return nil, err
	}
	secret, err := aead.Open(nil, nonce, ciphertext, []byte(credentialID))
	if err != nil {
		return nil, errors.New("holder secret decryption failed")
	}
	return secret, nil
}

func SavePseudonymToken(path string, token *PseudonymToken) error {
	if token == nil {
		return errors.New("token is nil")
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadPseudonymToken(path string) (*PseudonymToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var token PseudonymToken
	if err = json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("decode pseudonym token: %w", err)
	}
	return &token, nil
}

// SaveAppointmentToken stores the patient-held appointment token as JSON.
// It contains the ATI and must remain in the patient's protected wallet; it
// intentionally contains no PatientID, pseudonym, or provider identifier.
func SaveAppointmentToken(path string, token *AppointmentToken) error {
	if token == nil {
		return errors.New("appointment token is nil")
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

func LoadAppointmentToken(path string) (*AppointmentToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var token AppointmentToken
	if err = json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("decode appointment token: %w", err)
	}
	return &token, nil
}

// SavePseudonymPrivateKey stores the patient-held IBS private key in a
// separate AES-256-GCM encrypted JSON file. The caller is responsible for
// obtaining the wallet key from secure device storage.
func SavePseudonymPrivateKey(path string, key *PseudonymPrivateKey, walletKey []byte) error {
	if key == nil || key.KeyID == "" || key.PseudonymID == "" || key.APCVerificationMethod == "" || key.CreatedAt == "" {
		return errors.New("pseudonym private key metadata is incomplete")
	}
	if len(key.PrivateKey) == 0 {
		return errors.New("pseudonym private key is empty")
	}
	aead, err := newWalletAEAD(walletKey)
	if err != nil {
		return err
	}
	envelope := PseudonymPrivateKeyEnvelope{
		Version: 1, KeyType: "HIDM-ChaCheon-IBS-PseudonymPrivateKey-v1",
		KeyID: key.KeyID, PseudonymID: key.PseudonymID,
		APCVerificationMethod: key.APCVerificationMethod, CreatedAt: key.CreatedAt,
		Cipher: "AES-256-GCM",
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	envelope.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	sealed := aead.Seal(nil, nonce, key.PrivateKey, pseudonymKeyAAD(envelope))
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(sealed)
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateJSON(path, data)
}

// LoadPseudonymPrivateKey decrypts a separately stored patient IBS private
// key and verifies its authenticated metadata.
func LoadPseudonymPrivateKey(path string, walletKey []byte) (*PseudonymPrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope PseudonymPrivateKeyEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode pseudonym private key envelope: %w", err)
	}
	if envelope.Version != 1 || envelope.KeyType != "HIDM-ChaCheon-IBS-PseudonymPrivateKey-v1" || envelope.KeyID == "" || envelope.PseudonymID == "" || envelope.APCVerificationMethod == "" || envelope.CreatedAt == "" || envelope.Cipher != "AES-256-GCM" {
		return nil, errors.New("invalid pseudonym private key envelope")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, errors.New("invalid pseudonym private key nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid pseudonym private key ciphertext")
	}
	aead, err := newWalletAEAD(walletKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := aead.Open(nil, nonce, ciphertext, pseudonymKeyAAD(envelope))
	if err != nil {
		return nil, errors.New("pseudonym private key decryption failed")
	}
	return &PseudonymPrivateKey{KeyID: envelope.KeyID, PseudonymID: envelope.PseudonymID, APCVerificationMethod: envelope.APCVerificationMethod, CreatedAt: envelope.CreatedAt, PrivateKey: privateKey}, nil
}

func pseudonymKeyAAD(envelope PseudonymPrivateKeyEnvelope) []byte {
	metadata := struct {
		Version, KeyType, KeyID, PseudonymID, APCVerificationMethod, CreatedAt, Cipher string
	}{
		Version: fmt.Sprint(envelope.Version), KeyType: envelope.KeyType, KeyID: envelope.KeyID,
		PseudonymID: envelope.PseudonymID, APCVerificationMethod: envelope.APCVerificationMethod,
		CreatedAt: envelope.CreatedAt, Cipher: envelope.Cipher,
	}
	data, _ := json.Marshal(metadata)
	return data
}

func newWalletAEAD(walletKey []byte) (cipher.AEAD, error) {
	if len(walletKey) != 32 {
		return nil, errors.New("wallet key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(walletKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writePrivateJSON(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
