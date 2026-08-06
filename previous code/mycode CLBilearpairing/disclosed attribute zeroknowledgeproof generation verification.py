
# mmm.py
# This module implements the zero-knowledge proof system for verifying patient credentials
# in a privacy-preserving manner, using bilinear pairings and cryptographic commitments.
# It includes functions for generating and verifying zero-knowledge proofs.
# disclosed_attributes: 'biometric_data'

from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.pack import encode, decode
from petlib.bn import Bn
import json
import requests
import hashlib
import time
from datetime import date
import numpy as np


# File paths
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/patient_credential_signature.json"

# Define the fixed attribute order (must match the server)
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

# Initialize pairing group
group = BpGroup()
p = group.order()

def read_json_file(file_path):
    """
    Reads a JSON file from the given file path and returns the parsed JSON object.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # #print(f"Error: File not found at {file_path}")
        return None
    except json.JSONDecodeError:
        # #print(f"Error: Failed to parse JSON file at {file_path}")
        return None


# --- Commitment ---
def compute_aggregate_commitment(H, attributes):
    """Compute the aggregate commitment for a set of attributes."""
    commitment = group.gen1()  # Start with neutral element
    for i, attr_value in enumerate(attributes):
        commitment = commitment.add(H[i].mul(attr_value))
    return commitment


def credential_commitment_func(pk_user, aggregate_commitment):
    """Compute the credential commitment."""
    return pk_user.add(aggregate_commitment)


def verify_signature(signature, pk_issuer, credential_commitment, g2):
    """Verify the signature using pairing operations."""
    return group.pair(signature, g2) == group.pair(credential_commitment, pk_issuer)



# --- Zero-Knowledge Proof Generation ---
def generate_hidden_attribute_zk_proof(H, sk_user, hidden_attributes, nonce):
    """
    Generates a zero-knowledge proof for hidden attributes.
    """
    # Step 1: Generate random blinding factors
    tilde_sk_user = group.order().random()
    tilde_m = {i: group.order().random() for i in hidden_attributes}

    # Step 2: Compute the blinded commitment
    tilde_C = tilde_sk_user * group.gen1()
    for i, m_i in hidden_attributes.items():
        tilde_C += tilde_m[i] * H[i]  # Ensure H[i] is a G1Elem

    # Step 3: Generate challenge using the hash function
    tilde_C_serialized = tilde_C.export()
    nonce_serialized = encode(nonce)  # Serialize nonce as bytes
    data_to_hash = tilde_C_serialized + nonce_serialized
    c = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    # Step 4: Compute the responses
    masked_sk_user = tilde_sk_user + (c * sk_user)
    masked_hidden = {i: tilde_m[i] + (c * m_i) for i, m_i in hidden_attributes.items()}

    # #print("[DEBUG] Proof Generation")
    # #print(f"  tilde_C: {tilde_C}")
    # #print(f"  Challenge (c): {c}")
    # #print(f"  Masked sk_user: {masked_sk_user}")
    # #print(f"  Masked Hidden Attributes: {masked_hidden}")
    # #print(f"Generated Challenge (c): {c}")

    return c, masked_sk_user, masked_hidden, tilde_C



# --- Zero-Knowledge Proof Verification ---
def verify_hidden_attribute_zk_proof(c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1):
    """
    Verifies a zero-knowledge proof for hidden attributes.

    Implements the following verification steps:
    1. Recompute the blinded commitment using responses.
    2. Recompute the challenge as Hash(recomputed_commitment || nonce).
    3. Check if recomputed challenge matches the provided challenge.

    :param c: Challenge (Bn).
    :param masked_sk_user: Response for sk_user (Bn).
    :param masked_hidden: Dict mapping attribute indices to their responses (Bn).
    :param tilde_C: Original blinded commitment (G1Elem).
    :param H: List of attribute generators (G1Elem).
    :param nonce: Bn representing a nonce.
    :param C_hidden: Partial credential commitment for hidden attributes (G1Elem).
    :param g1: Generator for G1 (G1Elem).
    :return: Boolean indicating validity.
    """
    # Step 1: Recompute the blinded commitment using responses
    term1 = masked_sk_user * g1
    # #print(f"  [DEBUG] term1 (s_sk_user * g1): {term1}")

    term2 = G1Elem.inf(group)
    for i, s_hidden_i in masked_hidden.items():
        tmp = s_hidden_i * H[i]
        # #print(f"  [DEBUG] term2 partial (s_hidden[{i}] * H[{i}]): {tmp}")
        term2 += tmp
    # #print(f"  [DEBUG] term2 (sum of s_hidden[i] * H[i]): {term2}")

    cC = C_hidden * c
    # #print(f"  [DEBUG] cC (c * C_hidden): {cC}")

    tilde_C_prime = term1 + term2 - cC
    # #print(f"  [DEBUG] tilde_C_prime: {tilde_C_prime}")

    # Step 2: Recompute the challenge
    tilde_C_prime_serialized = tilde_C_prime.export()
    nonce_serialized = encode(nonce)
    data_to_hash = tilde_C_prime_serialized + nonce_serialized
    c_prime = Bn.from_binary(hashlib.sha256(data_to_hash).digest()).mod(p)

    # #print("[DEBUG] Proof Verification")
    # #print(f"  Original Challenge (c): {c}")
    # #print(f"  Recomputed Challenge (c'): {c_prime}")

    # Step 3: Validate the proof
    is_valid = c == c_prime
    # #print(f"  Zero-Knowledge Proof Valid: {is_valid}")
    return is_valid

#############################
# Main Function             #
#############################

# Load patient credential, public parameters
patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
parameters = read_json_file(PARAMETERS_FILE_PATH)
signature = decode(bytes.fromhex(patient_credential['signature']))

g1 = decode(bytes.fromhex(parameters['g1']))
g2 = decode(bytes.fromhex(parameters['g2']))
H = [decode(bytes.fromhex(h)) for h in parameters['H']]
sk_issuer = Bn.from_hex(parameters['sk_issuer'])
pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
sk_user = Bn.from_hex(parameters['sk_user'])
pk_user = decode(bytes.fromhex(parameters['pk_user']))

# #print("g1: ", g1)
# #print("g2: ", g2)
# #print("H: ", H)
# #print("sk_issuer: ", sk_issuer)
# #print("pk_issuer: ", pk_issuer)
# #print("pk_user: ", pk_user)

# Extract and process attribute values
attribute_values = []
for attr in ATTRIBUTE_ORDER:
    value = patient_credential['info'][attr]
    attr_hash = hashlib.sha256(value.encode()).digest()  # Hash the attribute value
    attr_bn = Bn.from_binary(attr_hash).mod(p)  # Convert hash to Bn and reduce modulo p
    attribute_values.append(attr_bn)

# Compute commitments and generate signature
aggregate_commitment = compute_aggregate_commitment(H, attribute_values)
credential_commitment = credential_commitment_func(pk_user, aggregate_commitment)

# Verify signature
# #print("=== Verify Signature ===")
signature_valid = verify_signature(signature, pk_issuer, credential_commitment, g2)
# #print(f"Signature Valid: {signature_valid}\n")

# Define which attributes are hidden and which are disclosed
hidden_attribute_indices = {
    0: attribute_values[0],  # 'credential_id'
    1: attribute_values[1],  # 'did_patient'
    2: attribute_values[2],  # 'patient_id'
    4: attribute_values[4],  # 'issue_date'
    5: attribute_values[5]   # 'did_apc'
}


disclosed_attribute_indices = {
    3: attribute_values[3]  # 'biometric_data'
}


# Generate a nonce
nonce = group.order().random()

# Generate ZK proof
c, masked_sk_user, masked_hidden, tilde_C = generate_hidden_attribute_zk_proof(
    H, sk_user, hidden_attribute_indices, nonce
)

# #print("=== Generate Zero-Knowledge Proof ===")
# #print(f"Hidden Attribute Indices and Values: {hidden_attribute_indices}")
# #print(f"Disclosed Attribute Indices and Values: {disclosed_attribute_indices}\n")

# Compute partial credential commitment for hidden attributes
C_hidden = (sk_user * g1)
for i, m_i in hidden_attribute_indices.items():
    C_hidden += H[i] * m_i
# #print(f"[DEBUG] Partial Credential Commitment (C_hidden): {C_hidden}\n")

# Verify ZK proof
# #print("=== ✨ ===")
# #print("c: ", c)
# #print("masked_sk_user: ", masked_sk_user)
# #print("masked_hidden: ", masked_hidden)
# #print("tilde_C: ", tilde_C)
# #print("H: ", H)
# #print("nonce: ", nonce)
# #print("C_hidden: ", C_hidden)
# #print("g1: ", g1)


# #print("=== Verify Zero-Knowledge Proof ===")
zk_valid = verify_hidden_attribute_zk_proof(
    c, masked_sk_user, masked_hidden, tilde_C, H, nonce, C_hidden, g1
)
print ("zk_valid: ", zk_valid)


proof_of_knowledge_patient_id_verification_parameters = {
    'signature': encode(signature).hex(),  # Serialize G1Elem to hex
    'credential_commitment': encode(credential_commitment).hex(),  # Serialize G1Elem to hex
    'c': c.hex(),  # Serialize Bn to hex
    'masked_sk_user': masked_sk_user.hex(),  # Serialize Bn to hex
    'masked_hidden': {i: val.hex() for i, val in masked_hidden.items()},  # Serialize Bn dict to hex
    'tilde_C': encode(tilde_C).hex(),  # Serialize G1Elem to hex
    'H': [encode(h).hex() for h in H],  # Serialize list of G1Elem to hex
    'nonce': nonce.hex(),  # Serialize Bn to hex
    'C_hidden': encode(C_hidden).hex(),  # Serialize G1Elem to hex
    'disclosed_attributes': patient_credential['info']['patient_id'],  # Leave as-is
}