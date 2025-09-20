import json
import hashlib
from sympy import mod_inverse


# --- Public parameters for Appointment Token ---
p_AT = 23
q_AT = 11
g_AT = 2
h_AT = 3  # independent generator for Pedersen commitment


# APC key public key
Y_APC = 13



def read_json_file(file_path):
    """
    Reads a JSON file from the given file path and returns the parsed JSON object.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON file at {file_path}")
        return None



def H_msg1_to_scalar(appointment_token_id: bytes) -> int:
    # Hash → Z_{q_AT} for the hidden attribute
    return H_to_q_bytes(appointment_token_id)



def H_to_q_bytes(*parts: bytes) -> int:
    h_ = hashlib.sha256()
    for part in parts:
        h_.update(part)
    return int.from_bytes(h_.digest(), "big") % q_AT


def int_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")



# --- Verification Appointment Token signature ---
def verify_appointment_token_signature(Y_APC: int, appointment_token_id: bytes, expiration_date: bytes,
           sig: tuple[int, int], t: int) -> bool:
    """Verifier checks that (s, c) is a valid partially blind signature."""
    s, c = sig

    # m1 and commit'
    m1 = H_msg1_to_scalar(appointment_token_id)
    commit_prime = (pow(g_AT, m1, p_AT) * pow(h_AT, t, p_AT)) % p_AT

    # cs' = Hash(Y_APC || expiration_date)
    cs_prime = H_to_q_bytes(int_bytes(Y_APC), expiration_date)

    # R'' = g^s · (Y_APC^c)^(-1)
    Y_c = pow(Y_APC, c, p_AT)
    inv_Y_c = mod_inverse(Y_c, p_AT)
    R_dd = (pow(g_AT, s, p_AT) * inv_Y_c) % p_AT

    # cu' = Hash(R'' || commit')
    cu_prime = H_to_q_bytes(int_bytes(R_dd), int_bytes(commit_prime))

    # accept iff c == cu' + cs' (mod q_AT)
    return c == (cu_prime + cs_prime) % q_AT





# Define the path directly
AT_credential_path = "/home/nmuslim162022/Desktop/mycode2/AT/AT_credential_signature.json"
AT_credential = read_json_file(AT_credential_path)
print ("AT_credential: ", AT_credential)

appointment_token_id_str = AT_credential["info"]["appointment_token_id"]
expiration_date_str = AT_credential["info"]["expiration_date"]

# Signature components (could be strings in JSON)
c = int(AT_credential["signature"]["c"])
s = int(AT_credential["signature"]["s"])
t = int(AT_credential["signature"]["t"])

# Convert to bytes for hashing
appointment_token_id_bytes = appointment_token_id_str.encode("utf-8")
expiration_date_bytes = expiration_date_str.encode("utf-8")

# Verify (note: function expects sig=(s, c) in that order)
is_valid = verify_appointment_token_signature(
    Y_APC=Y_APC,
    appointment_token_id=appointment_token_id_bytes,
    expiration_date=expiration_date_bytes,
    sig=(s, c),
    t=t
)

print("Signature verification:", "VALID" if is_valid else "INVALID")

