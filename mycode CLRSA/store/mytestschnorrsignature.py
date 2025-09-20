

from bplib.bp import BpGroup
from petlib.pack import encode, decode
import hashlib
import json

# Schnorr parameters (matching your earlier setup)
p1 = 162259276829213363391578010288127
q1 = 81129638414606681695789005144063
g1_schnorr = 2

file_path = "/home/nmuslim162022/Desktop/mycode/patient_pseudonym_data.json"

def read_json_file(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)

def group_element_to_hex(element):
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)

def group_element_to_scalar(elem):
    """Hash a group element to a scalar in Zq."""
    h = hashlib.sha256(encode(elem))
    scalar = int.from_bytes(h.digest(), 'big') % q1
    return scalar

def schnorr_signature_generate(msg_bytes, sk_sum):
    r = 123456789  # Use random in production!
    R = pow(g1_schnorr, r, p1)
    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + msg_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1
    s = (r - c * sk_sum) % q1
    return s, c

def schnorr_signature_verify(msg_bytes, s, c, Y_sum):
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sum, c, p1)) % p1
    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + msg_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1
    return c_prime == c

if __name__ == "__main__":
    group = BpGroup()
    pseudonym_data = read_json_file(file_path)
    P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'], group)
    P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'], group)

    # Step 1: Hash group elements to scalars
    sk_a = group_element_to_scalar(P_patient_a)
    sk_b = group_element_to_scalar(P_patient_b)

    # Step 2: Sum the scalars to form the signing key
    sk_sum = (sk_a + sk_b) % q1

    # Step 3: Public key for verification
    Y_sum = pow(g1_schnorr, sk_sum, p1)

    # Step 4: Prepare message
    message = "hello world"
    msg_bytes = message.encode("utf-8")

    # Step 5: Sign message
    s, c = schnorr_signature_generate(msg_bytes, sk_sum)
    print("Signature (using sk_sum):")
    print("s:", s)
    print("c:", c)
    print("Y_sum:", Y_sum)

    # Step 6: Verify
    valid = schnorr_signature_verify(msg_bytes, s, c, Y_sum)
    print("Signature valid?", valid)


