# patient_credential_signature_verification.py
# This script verifies the signature of a patient credential using RSA public key cryptography.
# It reads the public key from a PEM file, computes the digest of the credential,
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load public key
public_key_path = r'C:\Users\nasif\Desktop\mnmn\RSA\apc_public_key.pem'
def load_public_key(path):
    with open(path, "rb") as file:
        public_key = serialization.load_pem_public_key(file.read(), backend=default_backend())
    return public_key

def verify_rsa_signature(patient_credential, signature):
    public_key = load_public_key(public_key_path)
    credential_bytes = json.dumps(patient_credential['info'], sort_keys=True).encode("utf-8")
    digest = hashlib.md5(credential_bytes).digest()[:8]
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n
    signature_int = int.from_bytes(signature, byteorder='big')
    verified_digest_int = pow(signature_int, e, n)
    verified_digest = verified_digest_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')[-8:]
    return verified_digest == digest

patient_credential_path = r'C:\Users\nasif\Desktop\mnmn\RSA\patient_credential.json'
# Example usage:
with open(patient_credential_path, 'r') as f:
    cred = json.load(f)
signature_bytes = base64.b64decode(cred['signature'])
print("Verification result:", verify_rsa_signature(cred, signature_bytes))
