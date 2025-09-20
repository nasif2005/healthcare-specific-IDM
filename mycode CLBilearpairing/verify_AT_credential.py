# verify_at_signature.py
# # This script simulates a VERIFIER's actions to check the validity of a signed
# # Appointment Token (AT) credential. It does NOT create or modify any signatures.

import json
import hashlib
from bplib.bp import BpGroup
from petlib.pack import decode
from petlib.bn import Bn

# --- Configuration ---
# File paths for the public parameters and the credential to be verified.
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"
AT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/AT_credential_signature.json"

# --- Helper Functions (Identical to the signing script for consistency) ---
def read_json_file(file_path):
    """A simple utility to read and parse a JSON file."""
    with open(file_path, 'r') as file:
        return json.load(file)

def hash_and_reduce(attribute_string, group_order):
    """Hashes a string attribute and reduces it to a number in the finite field."""
    attribute_hash = hashlib.sha256(str(attribute_string).encode()).digest()
    return Bn.from_binary(attribute_hash).mod(group_order)

def recompute_at_commitment(pk_user, H, at_info, group_order):
    """
    Recomputes the commitment value from the public attributes of the AT.
    This function must be identical on both the issuer's and verifier's side.
    """
    # Hash the appointment token ID to a scalar.
    m_token = hash_and_reduce(at_info['appointment_token_id'], group_order)
    # C_token = pk_user + m_token * H_0
    commitment_token = pk_user + H[0].mul(m_token)
    
    # Hash the expiration date to a scalar.
    m_exp = hash_and_reduce(at_info['expiration_date'], group_order)
    # C_exp = m_exp * H_1
    commitment_exp_date = H[1].mul(m_exp)
    
    # The final commitment is the sum of the individual commitments.
    return commitment_token + commitment_exp_date

# --- Core Verification Logic ---

def verify_at_signature(signature_elem, commitment_elem, pk_issuer_elem, group):
    """
    Verifies the AT signature using a bilinear pairing equation.
    
    The signature was created as: sig = commitment * sk_issuer
    The verification equation is: e(sig, g2) == e(commitment, pk_issuer)
    where pk_issuer = g2 * sk_issuer. This works due to the bilinearity of pairings.
    """
    # Get the public generator for group G2.
    g2 = group.gen2()
    
    # Calculate the Left-Hand Side (LHS) of the pairing equation.
    # LHS = e(signature, g2)
    lhs = group.pair(signature_elem, g2)
    
    # Calculate the Right-Hand Side (RHS) of the pairing equation.
    # RHS = e(commitment, pk_issuer)
    rhs = group.pair(commitment_elem, pk_issuer_elem)
    
    # The signature is valid if and only if the two pairing results are equal.
    return lhs == rhs

# --- Main Execution Block ---
if __name__ == "__main__":
    print("--- Verifying the signature of an AT Credential ---")
    
    # Initialize the elliptic curve group.
    group = BpGroup()
    p = group.order()

    # --- Step 1: Load all necessary public data and the signature ---
    
    # Load the credential we want to verify.
    at_credential = read_json_file(AT_CREDENTIAL_FILE_PATH)
    at_credential_info = at_credential['info']
    signature_hex = at_credential['signature']
    
    # Load the public parameters file.
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    # NOTE: The verifier ONLY uses PUBLIC keys. It does not load/use sk_issuer.
    H_hex = parameters['H']
    pk_issuer_hex = parameters['pk_issuer']
    pk_user_hex = parameters['pk_user']

    # --- Step 2: Deserialize all hexadecimal strings into cryptographic objects ---
    
    # Deserialize the signature from the credential file into a G1 element.
    signature_to_verify = decode(bytes.fromhex(signature_hex))
    
    # Deserialize the public parameters.
    H = [decode(bytes.fromhex(h)) for h in H_hex]
    pk_issuer = decode(bytes.fromhex(pk_issuer_hex)) # Issuer's Public Key is in G2
    pk_user = decode(bytes.fromhex(pk_user_hex))     # User's Public Key is in G1
    
    # --- Step 3: Recompute the commitment ---
    # The verifier independently re-calculates the commitment based on the public
    # information in the credential's 'info' block.
    print("\nRecomputing commitment from credential attributes...")
    commitment = recompute_at_commitment(
        pk_user,
        H,
        at_credential_info,
        p
    )
    print("Commitment recomputed successfully.")

    # --- Step 4: Perform the verification ---
    # Call the verification function with the deserialized signature, the recomputed
    # commitment, and the issuer's public key.
    print("\nPerforming pairing-based signature verification...")
    is_valid = verify_at_signature(
        signature_to_verify,
        commitment,
        pk_issuer,
        group
    )

    # --- Step 5: Display the final result ---
    print("\n--- VERIFICATION RESULT ---")
    if is_valid:
        print("✅ The AT signature is VALID.")
    else:
        print("❌ The AT signature is INVALID.")