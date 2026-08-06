### The PRE scheme based on asymmetric pairing

from bplib.bp import BpGroup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from bplib.bp import Bn

# Initialize pairing group (default BN254)
group = BpGroup()

# --- Public Parameters ---
# Generator of the groups G1 and G2
g1 = group.gen1()
g2 = group.gen2()

# Pairing result
z = group.pair(g1, g2)

# --- Key Generation ---
# a. Patient Keys
sk_patient = group.order().random()  # Private key of patient
pk_patient = g2 * sk_patient         # Public key of patient

# b. HRR Keys
sk_HRR = group.order().random()      # Private key of HRR
pk_HRR = g1 * sk_HRR                 # Public key of HRR

# --- Helper Functions ---

def derive_key(pid_enc_element):
    """Derive a symmetric key from pid_enc using SHA-256."""
    pid_enc_bytes = pid_enc_element.export()  # Export element to bytes
    hash_obj = SHA256.new(pid_enc_bytes)
    return hash_obj.digest()  # 32-byte symmetric key


def encrypt_pid(pid, key):
    """Encrypt the PID using AES with the derived key."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(str(pid).encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption

def decrypt_pid(encrypted_pid, key):
    """Decrypt the PID using AES with the derived key."""
    iv = encrypted_pid[:16]
    ct = encrypted_pid[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return int(pt.decode('utf-8'))


def patient_computation(pid):
    """Computation by the patient."""
    # Convert PID into a Bn object
    pid_h = Bn(pid)

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
    # rk = pk_HRR^(1/sk_patient) where mod_inverse calculates the modular multiplicative inverse

    return P_patient_a, P_patient_b, rk_patient_to_HRR, encrypted_pid


def healthcare_provider_computation(P_patient_a, P_patient_b, rk_patient_to_HRR):
    """Re-encryption by the healthcare provider."""
    # Re-encrypt the pseudonym
    P_HRR_a = P_patient_a  # remains unchanged
    P_HRR_b = group.pair(rk_patient_to_HRR, P_patient_b)  # Swap arguments for correct pairing
    return P_HRR_a, P_HRR_b

def HRR_computation(P_HRR_a, P_HRR_b, encrypted_pid):
    """Decryption by HRR."""
    # Compute inverse exponent in ZR
    exponent = sk_HRR.mod_inverse(group.order())
    
    # Compute the decrypted `pid_enc`
    PID_enc_decrypted = P_HRR_a * (P_HRR_b ** -exponent)  # Use ** for exponentiation and inverse

    # Derive the symmetric key from the decrypted `pid_enc`
    symmetric_key_decrypted = derive_key(PID_enc_decrypted)

    # Decrypt the PID
    pid_decrypted = decrypt_pid(encrypted_pid, symmetric_key_decrypted)

    return pid_decrypted


# --- Add this helper ---
def proxy_verify_rk_binding(rk_patient_to_HRR, pk_patient, pk_HRR):
    """
    Check that rk = (1/x) * pk_HRR for the same pk_patient = x*g2 and pk_HRR = y*g1.
    Equivalently: e(rk, pk_patient) == e(pk_HRR, g2).
    """
    left  = group.pair(rk_patient_to_HRR, pk_patient)  # e(G1, G2)
    right = group.pair(pk_HRR, g2)                     # e(G1, G2)
    return left == right




# --- Main Functionality ---
if __name__ == "__main__":
    pid = 1  # Example patient identifier

    # Patient computation
    P_patient_a, P_patient_b, rk_patient_to_HRR, encrypted_pid = patient_computation(pid)

    print("P_patient_a:", P_patient_a)
    print("P_patient_b:", P_patient_b)
    print("rk_patient_to_HRR:", rk_patient_to_HRR)

    # Healthcare provider computation
    value = proxy_verify_rk_binding(rk_patient_to_HRR, pk_patient, pk_HRR)
    print ("value: ", value)
    P_HRR_a, P_HRR_b = healthcare_provider_computation(P_patient_a, P_patient_b, rk_patient_to_HRR)

    print("P_HRR_a:", P_HRR_a)
    print("P_HRR_b:", P_HRR_b)

    # HRR computation
    decrypted_pid = HRR_computation(P_HRR_a, P_HRR_b, encrypted_pid)

    print("Decrypted PID:", decrypted_pid)
