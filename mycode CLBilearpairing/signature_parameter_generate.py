import json
from bplib.bp import BpGroup
from petlib.pack import encode, decode

# Initialize pairing group (using BN254 by default in bplib)
group = BpGroup()
p = group.order()  # Prime order of the group


# --- Public Parameters Setup ---
ATTRIBUTE_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']


# Serialization and Deserialization
def group_element_to_hex(element):
    """Serialize a group element and convert it to a hex string."""
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)


# --- Public Parameters Setup ---
def setup():
    """
    Sets up the public parameters for the cryptographic scheme.

    :return: Tuple containing the generator g1, generator g2, and list of attribute generators H.
    """
    g1 = group.gen1()  # Generator of G1
    g2 = group.gen2()  # Generator of G2
    H = [g1 * group.order().random() for _ in range(len(ATTRIBUTE_ORDER))]  # Randomized generators for attributes in G1
    return g1, g2, H


# --- Issuer Key Generation ---
def issuer_key_gen(g2):
    sk_issuer = group.order().random()  # Issuer's private key
    pk_issuer = g2 * sk_issuer  # Issuer's public key in G2
    return sk_issuer, pk_issuer

# --- User Key Generation ---
def user_key_gen(g1):
    sk_user = group.order().random()  # User's private key
    pk_user = g1 * sk_user  # User's public key in G1
    return sk_user, pk_user


# Step 1: Setup public parameters
g1, g2, H = setup()
print("g1 (Generator 1):", g1)
print("g2 (Generator 2):", g2)
print("H:", H)

# Step 2: Key generation
sk_issuer, pk_issuer = issuer_key_gen(g2)  # Issuer's keys in G2
sk_user, pk_user = user_key_gen(g1)       # User's keys in G1

# Print keys and parameters in hexadecimal
print("g1 (Generator 1):", group_element_to_hex(g1))
print("g2 (Generator 2):", group_element_to_hex(g2))
print("H (Attribute Generators):", [group_element_to_hex(h) for h in H])

print("sk_issuer (Private Key):", sk_issuer.hex())
print("pk_issuer (Public Key):", group_element_to_hex(pk_issuer))

print("sk_user (Private Key):", sk_user.hex())
print("pk_user (Public Key):", group_element_to_hex(pk_user))

# File path to store the values
FILE_PATH = "/home/nmuslim162022/Desktop/mycode2/crypto_parameters.json"


def save_values(file_path, values):
    """Save values to a JSON file."""
    with open(file_path, "w") as file:
        json.dump(values, file, indent=4)


# Store values to be saved
values_to_save = {
    "g1": group_element_to_hex(g1),
    "g2": group_element_to_hex(g2),
    "H": [group_element_to_hex(h) for h in H],
    "sk_issuer": sk_issuer.hex(),
    "pk_issuer": group_element_to_hex(pk_issuer),
    "sk_user": sk_user.hex(),
    "pk_user": group_element_to_hex(pk_user)
}        


# Save values
save_values(FILE_PATH, values_to_save)
print(f"Values saved to {FILE_PATH}")
