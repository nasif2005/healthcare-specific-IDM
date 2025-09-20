import hashlib
import json
from petlib.bn import Bn
from bplib.bp import BpGroup
from petlib.pack import encode, decode

# ==============================================================================
# 1. GLOBAL PUBLIC PARAMETERS and SETUP
# ==============================================================================

# Initialize the pairing-based cryptographic group (e.g., BN254)
group = BpGroup()

# Define the global public parameters from the group
g1, g2 = group.gen1(), group.gen2()
z = group.pair(g1, g2)

print("--- System Setup Complete ---")
print("Global public parameters (group, g1, g2, z) are now defined.")

# ==============================================================================
# 2. HELPER FUNCTIONS
# ==============================================================================

def group_element_to_hex(element):
    """Serialize a group element to a hex string."""
    return encode(element).hex()

def hex_to_group_element(hex_str):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)

# ==============================================================================
# 3. NIZK PROOF IMPLEMENTATION (APPENDIX A)
# ==============================================================================

def generate_binding_proof(P_patient_a, P_patient_b, r, pk_patient, patient_id_str):
    """
    Generates a NIZK proof for binding the patient credential and pseudonym.
    """
    print("\n--- Generating NIZK Binding Proof (Patient's Side) ---")

    # 1. Choose random scalars t1, t2
    t1 = group.order().random()
    t2 = group.order().random()

    # 2. Compute commitments T1 (in GT) and T2 (in G2)
    T1 = z ** t1
    T2 = pk_patient * t2
    print("Step 1 & 2: Commitments T1, T2 generated.")

    # 3. Compute Fiat-Shamir challenge 'c'
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()

    hasher = hashlib.sha256()
    hasher.update(encode(P_patient_a))
    hasher.update(encode(P_patient_b))
    hasher.update(encode(T1))
    hasher.update(encode(T2))
    hasher.update(encode(pk_patient))
    hasher.update(encode(patient_id_fr))
    
    c = Bn.from_hex(hasher.hexdigest()) % group.order()
    print(f"Step 3: Fiat-Shamir Challenge 'c' computed.")

    # 4. Compute responses s1, s2
    s1 = (t1 + c * r) % group.order()
    s2 = (t2 + c * r) % group.order()
    print("Step 4: Responses 's1' and 's2' computed.")

    # 5. Assemble the final proof
    proof = {
        "T1": group_element_to_hex(T1),
        "T2": group_element_to_hex(T2),
        "c": c.hex(),
        "s1": s1.hex(),
        "s2": s2.hex()
    }
    
    print("Step 5: NIZK Proof generated successfully.")
    return proof

def verify_binding_proof(proof, P_patient_a, P_patient_b, pk_patient, patient_id_str):
    """
    Verifies the NIZK proof of binding.
    """
    print("\n--- Verifying NIZK Binding Proof (PTA's Side) ---")

    # Unpack the proof components
    T1 = hex_to_group_element(proof['T1'])
    T2 = hex_to_group_element(proof['T2'])
    c = Bn.from_hex(proof['c'])
    s1 = Bn.from_hex(proof['s1'])
    s2 = Bn.from_hex(proof['s2'])

    # Recompute Hash(PatientID)
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()
    
    # -- Verification Equation 1 (in GT, multiplicative) --
    print("Verifying Equation 1...")
    lhs1 = z ** s1
    patient_id_gt = z ** patient_id_fr
    p1_div_hash = P_patient_a * (patient_id_gt ** -1) 
    rhs1 = T1 * (p1_div_hash ** c)
    check1 = (lhs1 == rhs1)
    print(f"Verification Check 1 (in GT): {'PASSED' if check1 else 'FAILED'}")

    # -- Verification Equation 2 (in G2, additive) --
    print("Verifying Equation 2...")
    lhs2 = pk_patient * s2
    rhs2 = T2 + (P_patient_b * c)
    check2 = (lhs2 == rhs2)
    print(f"Verification Check 2 (in G2): {'PASSED' if check2 else 'FAILED'}")
    
    return check1 and check2

# ==============================================================================
# 4. DEMONSTRATION
# ==============================================================================

if __name__ == "__main__":
    
    # --- Load All Necessary Parameters from a Single, Consistent File ---
    print("\n--- Loading All Parameters from JSON file ---")
    
    file_path = "/home/nmuslim162022/Desktop/mycode/patient_pseudonym_data.json"
    try:
        with open(file_path, 'r') as f:
            pseudonym_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {file_path} not found. Please run 'pseudonym_keygeneration.py' first.")
        exit()

    # ################### UPDATES ARE HERE ###################
    # Get the patient_id from the file to ensure consistency
    patient_id = pseudonym_data.get("patient_id", "PT-0001") # Use .get for safety

    # Deserialize ALL loaded hex strings into cryptographic objects
    P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'])
    P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'])
    r = Bn.from_hex(pseudonym_data['r'])
    # Load the public key from the file to match the one used for pseudonym generation
    pk_patient = hex_to_group_element(pseudonym_data['pk_patient'])
    # ########################################################

    print("Pseudonym, secret 'r', and patient's public key 'pk_patient' loaded successfully.")
    print(f"Verifying for Patient ID: {patient_id}")

    # --- NIZK Proof Generation (Patient's Side) ---
    # The patient uses the loaded pseudonym and secret 'r' to generate the proof
    binding_proof = generate_binding_proof(
        P_patient_a, P_patient_b, r, pk_patient, patient_id
    )
    
    print("\nGenerated Proof:")
    print(json.dumps(binding_proof, indent=2))
    
    # --- NIZK Proof Verification (PTA's Side) ---
    # The PTA receives the pseudonym and the newly generated proof
    is_valid = verify_binding_proof(
        binding_proof, P_patient_a, P_patient_b, pk_patient, patient_id
    )
    
    print("\n--- Final Result ---")
    if is_valid:
        print("✅ The NIZK proof is VALID. The PTA can trust the binding between the pseudonym and the PatientID.")
    else:
        print("❌ The NIZK proof is INVALID. The request should be rejected.")