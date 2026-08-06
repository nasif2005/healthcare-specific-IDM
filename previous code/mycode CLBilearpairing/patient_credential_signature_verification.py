# verify_patient_credential.py (Corrected)
import json
import hashlib
from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.pack import decode
from petlib.bn import Bn

# --- Configuration ---
# Define file paths to the credential and public parameters
PATIENT_CREDENTIAL_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/patient_credential_signature.json"
PARAMETERS_FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"

# The order of attributes is critical and must match the order used during issuance.
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']

# --- Helper Functions ---

def read_json_file(file_path):
    """Reads and parses a JSON file, handling potential errors."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"FATAL ERROR: File not found at {file_path}")
        exit(1)
    except json.JSONDecodeError:
        print(f"FATAL ERROR: Could not parse JSON file at {file_path}")
        exit(1)

def hash_and_reduce(attribute_string, group_order):
    """
    Hashes a string attribute and reduces it modulo the group order.
    This must exactly match the hashing scheme used by the issuer.
    """
    # Hash the attribute using SHA-256
    attribute_hash = hashlib.sha256(attribute_string.encode()).digest()
    # Convert the hash bytes to a big number (Bn) and reduce it
    return Bn.from_binary(attribute_hash).mod(group_order)

def recompute_credential_commitment(group, pk_user, H, attributes_dict, attribute_order, g1, group_order):
    """
    Recomputes the credential commitment from public information.
    C = pk_user + g1 + m_0*H_0 + m_1*H_1 + ...
    """
    print("  Step 2a: Hashing attributes and computing aggregate commitment...")
    
    # NOTE: The provided issuance scripts incorrectly add `g1` to the commitment.
    # To successfully verify a signature from those scripts, we must replicate that behavior here.
    # A standard CL scheme would initialize with G1Elem.inf(group).
    
    # --- THIS IS THE CORRECTED LINE ---
    aggregate_commitment = g1
    # ---------------------------------

    for i, attr_name in enumerate(attribute_order):
        attr_value_str = attributes_dict[attr_name]
        # Hash and reduce the attribute value to a number 'm_i'
        m_i = hash_and_reduce(attr_value_str, group_order)
        # Add the attribute's contribution (m_i * H_i) to the commitment
        aggregate_commitment += H[i].mul(m_i)
        print(f"    - Processed attribute '{attr_name}'")

    print("  Step 2b: Adding patient public key (pk_user) to finalize commitment...")
    # The final credential commitment is the sum of the user's public key and the aggregate attribute commitment
    credential_commitment = pk_user.add(aggregate_commitment)
    
    return credential_commitment

def verify_cl_signature(group, signature, credential_commitment, pk_issuer, g2):
    """
    Performs the bilinear pairing check to verify the signature.
    Verification equation: e(signature, g2) = e(credential_commitment, pk_issuer)
    """
    # Compute the left-hand side of the pairing equation
    lhs = group.pair(signature, g2)
    
    # Compute the right-hand side of the pairing equation
    rhs = group.pair(credential_commitment, pk_issuer)
    
    # The signature is valid if and only if both sides are equal
    return lhs == rhs

# --- Main Verification Logic ---

if __name__ == "__main__":
    print("--- Starting Patient Credential Signature Verification ---")
    
    # Initialize the bilinear pairing group
    group = BpGroup()
    p = group.order()

    # 1. Load data from files
    print("\nStep 1: Loading credential, signature, and public parameters...")
    patient_credential = read_json_file(PATIENT_CREDENTIAL_FILE_PATH)
    parameters = read_json_file(PARAMETERS_FILE_PATH)
    print("  - Files loaded successfully.")

    # Deserialize all necessary cryptographic elements from hex strings
    try:
        # The signature to be verified (G1 element)
        signature = decode(bytes.fromhex(patient_credential['signature']))
        
        # Public parameters from the trusted setup (G1, G2, H)
        g1 = decode(bytes.fromhex(parameters['g1']))
        g2 = decode(bytes.fromhex(parameters['g2']))
        H = [decode(bytes.fromhex(h)) for h in parameters['H']]
        
        # Issuer's public key (G2 element)
        pk_issuer = decode(bytes.fromhex(parameters['pk_issuer']))
        
        # Patient's public key (G1 element)
        pk_user = decode(bytes.fromhex(parameters['pk_user']))
        print("  - Cryptographic elements deserialized.")
    except (KeyError, ValueError) as e:
        print(f"FATAL ERROR: A required key is missing or data is malformed in the JSON files. Details: {e}")
        exit(1)

    # 2. Recompute the credential commitment
    print("\nStep 2: Recomputing the credential commitment from public attributes...")
    # The verifier must re-calculate this value themselves
    recomputed_commitment = recompute_credential_commitment(
        group,
        pk_user,
        H,
        patient_credential['info'],
        ATTRIBUTE_ORDER,
        g1,
        p
    )
    print("  - Credential commitment recomputed.")

    # 3. Perform the final verification
    print("\nStep 3: Performing bilinear pairing check...")
    is_valid = verify_cl_signature(group, signature, recomputed_commitment, pk_issuer, g2)
    print("  - Pairing check complete.")

    # 4. Display the final result
    print("\n--- Verification Result ---")
    if is_valid:
        print("✅ SIGNATURE IS VALID.")
        print("The signature correctly corresponds to the attributes listed in the credential.")
    else:
        print("❌ SIGNATURE IS INVALID.")
        print("The signature does not match the credential attributes or has been tampered with.")