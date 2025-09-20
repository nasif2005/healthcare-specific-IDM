

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

# --- Helper Functions ---

def derive_key(pid_enc_element):
    pid_enc_bytes = encode(pid_enc_element)
    hash_obj = SHA256.new(pid_enc_bytes)
    return hash_obj.digest()

def encrypt_pid(pid, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(str(pid).encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_pid(encrypted_pid, key):
    iv = encrypted_pid[:16]
    ct = encrypted_pid[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return int(pt.decode('utf-8'))

# Serialization and Deserialization
def group_element_to_hex(element):
    """Serialize a group element and convert it to a hex string."""
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)

def patient_computation(pid):
    """Computation by the patient."""
    # Convert PID into a Bn object
    pid_h = Bn.from_num(pid)

    # Map hashed PID to GT (pid_enc)
    pid_enc = z ** pid_h  # pid_enc ∈ GT

    # Generate a random value r in ZR
    r = group.order().random()

    # Derive the symmetric key for encryption
    symmetric_key = derive_key(pid_enc)

    # Encrypt the PID
    encrypted_pid = encrypt_pid(pid, symmetric_key)

    # Compute P_patient = (P_patient_a, P_patient_b)
    P_patient_a = (z ** r) * pid_enc  # P_patient_a = z^r * pid_enc (in GT)
    P_patient_b = pk_patient * r      # P_patient_b = pk_patient^r (in G2)

    # Re-encryption key generation
    rk_patient_to_HRR = pk_HRR * sk_patient.mod_inverse(group.order())
    # rk = pk_HRR^(1/sk_patient)

    return P_patient_a, P_patient_b, rk_patient_to_HRR, encrypted_pid


def healthcare_provider_computation(P_patient_a, P_patient_b, rk_patient_to_HRR):
    """Re-encryption by the healthcare provider."""
    # Re-encrypt the pseudonym
    P_HRR_a = P_patient_a  # remains unchanged
    P_HRR_b = group.pair(rk_patient_to_HRR, P_patient_b)  # Swap arguments for correct pairing
    return P_HRR_a, P_HRR_b


def HRR_computation(P_HRR_a, P_HRR_b, encrypted_pid, sk_HRR):
    """Decryption by HRR."""
    # Compute inverse exponent in ZR
    exponent = sk_HRR.mod_inverse(group.order())

    # Compute the decrypted pid_enc
    PID_enc_decrypted = P_HRR_a * (P_HRR_b ** -exponent)  # Use ** for exponentiation and inverse

    # Derive the symmetric key from the decrypted pid_enc
    symmetric_key_decrypted = derive_key(PID_enc_decrypted)

    # Decrypt the PID
    pid_decrypted = decrypt_pid(encrypted_pid, symmetric_key_decrypted)

    return pid_decrypted


# main function
if __name__ == "__main__":

    print ("sk_patient: ", sk_patient)
    print ("pk_patient: ", pk_patient)

    # Serialize and store HRR's key pair
    hrr_key_data = {
        "sk_HRR": sk_HRR.hex(),  # Correctly serialize sk_HRR as an integer
        "pk_HRR": group_element_to_hex(pk_HRR)  # Serialize public key as hex
    }

    print ("sk_HRR: ", sk_HRR.hex())
    print ("pk_HRR: ", group_element_to_hex(pk_HRR))


    # Save HRR's keys to a JSON file
    hrr_file_path = "/home/nasif/Desktop/my code/privacy preserving healthcare/patient pseudonym management/hrr_key_data.json"
    with open(hrr_file_path, "w") as json_file:
        json.dump(hrr_key_data, json_file, indent=4)

    pid = 1

    # Patient computation
    P_patient_a, P_patient_b, rk_patient_to_HRR, encrypted_pid = patient_computation(pid)
    
    print ("P_patient_a: ", group_element_to_hex(P_patient_a))
    print ("P_patient_b: ", group_element_to_hex(P_patient_b))
    print ("rk_patient_to_HRR: ", group_element_to_hex(rk_patient_to_HRR))
    print ("encrypted_pid: ", encrypted_pid.hex())


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



    # Save patient pseudonym data to a JSON file
    file_path = "/home/nasif/Desktop/my code/privacy preserving healthcare/patient pseudonym management/patient_pseudonym_data.json"
    with open(file_path, "w") as json_file:
        json.dump(data_to_store, json_file, indent=4)


    # Read JSON data from file    
    def read_json_file(file_path):
        with open(file_path, "r") as json_file:
            return json.load(json_file)

    pseudonym_data = read_json_file(file_path)
    print ("pseudonym_data: ", pseudonym_data)

    # Deserialize data
    print ("pseudonym_data['info']['P_patient_a']: ", pseudonym_data['info']['P_patient_a'])
    print ("pseudonym_data['info']['P_patient_b']: ", pseudonym_data['info']['P_patient_b'])
    print ("pseudonym_data['info']['rk_patient_to_HRR']: ", pseudonym_data['info']['rk_patient_to_HRR'])

    # Convert hex strings to group elements
    P_patient_a1 = hex_to_group_element(pseudonym_data['info']['P_patient_a'], group)
    P_patient_b1 = hex_to_group_element(pseudonym_data['info']['P_patient_b'], group)
    rk_patient_to_HRR1 = hex_to_group_element(pseudonym_data['info']['rk_patient_to_HRR'], group)
    encrypted_pid1 = bytes.fromhex(pseudonym_data['info']['encrypted_pid'])
    c = pseudonym_data["signature"]["c"]
    s = pseudonym_data["signature"]["s"]
    Y_sign = pseudonym_data["signature"]["Y_sign"]

    # Prepare the pseudonym token as a concatenated byte string for verification
    pseudonym_token_bytes = (
        bytes.fromhex(group_element_to_hex(P_patient_a1)) +
        bytes.fromhex(group_element_to_hex(P_patient_b1)) +
        bytes.fromhex(group_element_to_hex(rk_patient_to_HRR1)) +
        bytes.fromhex(encrypted_pid1.hex())
    )


    # Verify the Schnorr signature from the JSON file
    is_valid = schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign)
    print("\nSchnorr Signature Validity2:", "Valid" if is_valid else "Invalid")


    # Healthcare provider computation (optional)
    P_HRR_a, P_HRR_b = healthcare_provider_computation(P_patient_a, P_patient_b, rk_patient_to_HRR)
    print("P_HRR_a:", group_element_to_hex(P_HRR_a))
    print("P_HRR_b:", group_element_to_hex(P_HRR_b))

    P_HRR_a1, P_HRR_b1 = healthcare_provider_computation(P_patient_a1, P_patient_b1, rk_patient_to_HRR1)
    print ("P_HRR_a1: ", group_element_to_hex(P_HRR_a1))
    print ("P_HRR_b1: ", group_element_to_hex(P_HRR_b1))

    pseudonym_str = str(P_patient_a1) + str(P_patient_b1)                      # Concatenate the pseudonym components                
    patient_pseudonym = hashlib.sha256(pseudonym_str.encode()).hexdigest()   # Hash the pseudonym to get a unique identifier  
    print ("Patient Pseudonym 🍆: ", patient_pseudonym)

    # Read JSON data from file    
    def read_json_file(file_path):
        with open(file_path, "r") as json_file:
            return json.load(json_file)

    hrr_data = read_json_file(hrr_file_path)
    print ("hrr_data: ", hrr_data)

    # Deserialize the values from JSON
    #sk_HRR1 = hrr_data["sk_HRR"]
    #pk_HRR1 = hrr_data["pk_HRR"]

    # Deserialize the values from JSON
    sk_HRR1_hex = hrr_data["sk_HRR"]
    sk_HRR1 = Bn.from_hex(sk_HRR1_hex)  # Convert hex string back to Bn object
    pk_HRR1 = hex_to_group_element(hrr_data["pk_HRR"], group)


    print ("sk_HRR: ", sk_HRR)
    print ("sk_HRR1: ", sk_HRR1)


    # HRR computation (optional)
    decrypted_pid = HRR_computation(P_HRR_a1, P_HRR_b1, encrypted_pid, sk_HRR1)
    print("Decrypted PID:", decrypted_pid)
