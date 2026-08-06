
from bplib.bp import BpGroup
from petlib.pack import encode, decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from petlib.bn import Bn
import hashlib
import json


# Initialize pairing group (default BN254)
group = BpGroup()


# --- Public Parameters ---
g1 = group.gen1()
g2 = group.gen2()
z = group.pair(g1, g2)

# --- Key Generation ---
sk_patient = group.order().random()
pk_patient = g2 * sk_patient

sk_HRR = group.order().random()
pk_HRR = g1 * sk_HRR


# Define discrete log group parameters for Schnorr signature
p1 = 162259276829213363391578010288127  # A large prime number
q1 = 81129638414606681695789005144063   # A prime divisor of p1 - 1
g1_schnorr = 2  # Generator for the subgroup of order q1

# Generate Schnorr signing key pair
x_sign = 563452374  # Private key (example)
Y_sign = pow(g1_schnorr, x_sign, p1)  # Public key




# 
file_path = "/home/nmuslim162022/Desktop/mycode/patient_pseudonym_data.json"

# Read JSON data from file    
def read_json_file(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)
    

# Serialization and Deserialization
def group_element_to_hex(element):
    """Serialize a group element and convert it to a hex string."""
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)    
    


def schnorr_signature_generate(pseudonym_token_bytes, x_sign):
    """
    Generate a Schnorr signature using the finite field parameters.
    """
    r = 123456789  # Example fixed random nonce for testing
    R = pow(g1_schnorr, r, p1)  # Compute R = g^r mod p

    # Compute the challenge
    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1

    # Compute the signature component s
    s = (r - c * x_sign) % q1

    return s, c  # Return signature (s, c)


def schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign):
    """
    Verify a Schnorr signature.
    """
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sign, c, p1)) % p1  # R' = g^s * Y^c mod p

    # Compute the hash challenge
    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1

    # Check if the computed c_prime matches the original c
    return c_prime == c


# 
pseudonym_data = read_json_file(file_path)
print ("pseudonym_data: ", pseudonym_data)


# Convert hex strings to group elements
P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'], group)
P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'], group)
rk_patient_to_HRR = hex_to_group_element(pseudonym_data['rk_patient_to_HRR'], group)
encrypted_pid = bytes.fromhex(pseudonym_data['encrypted_pid'])



# Prepare the pseudonym token as a concatenated byte string for verification
pseudonym_token_bytes = (
    bytes.fromhex(group_element_to_hex(P_patient_a)) +
    bytes.fromhex(group_element_to_hex(P_patient_b)) +
    bytes.fromhex(group_element_to_hex(rk_patient_to_HRR)) +
    bytes.fromhex(encrypted_pid.hex())
)


# Generate Schnorr signature
s, c = schnorr_signature_generate(pseudonym_token_bytes, x_sign)
print("\nSignature generated:")
print("s:", s)
print("c:", c)
print("Y_sign:", Y_sign)

# Serialize and store data
data_to_store = {

    "info": {
        "P_patient_a": group_element_to_hex(P_patient_a),
        "P_patient_b": group_element_to_hex(P_patient_b),
        "rk_patient_to_HRR": group_element_to_hex(rk_patient_to_HRR),
        "encrypted_pid": encrypted_pid.hex()
        },
    "signature": {
        "c": c,
        "s": s,
        "Y_sign": Y_sign  # Directly convert Y_sign to hex since it's an integer
        }
    }



# Save (optional)
with open("/home/nmuslim162022/Desktop/mycode/signed_pseudonym_token.json", "w") as f:
    json.dump(data_to_store, f, indent=2)

# --- Example Verification ---
valid = schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign)
print("\nSignature valid:", valid)
    



