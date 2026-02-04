import secrets
import hashlib
import hmac
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ==========================================
# CONFIGURATION (Based on Section IV-A)
# ==========================================
N_KEYS = 128       # Number of keys in the vault (n)
KEY_SIZE_BITS = 128 # Size of each key in bits (m)
KEY_SIZE_BYTES = KEY_SIZE_BITS // 8
P_INDICES = 10     # Number of keys to XOR for a challenge (p)

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def cprint(c: str | None, msg: str):
    """Colored print for better visibility in logs."""
    if c is None:
        print(msg)
        return
    if c == 'g' or c == 'green':
        print(f"\033[92m{msg}\033[0m")
        return
    elif c == 'y' or c == 'yellow':
        print(f"\033[93m{msg}\033[0m")
        return
    elif c == 'r' or c == 'red':
        print(f"\033[91m{msg}\033[0m")
        return
    elif c == 'b' or c == 'blue':
        print(f"\033[94m{msg}\033[0m")
        return
    else:
        print(msg)

def xor_bytes(b1, b2):
    """XOR two byte strings of equal length."""
    if len(b1) != len(b2):
        raise ValueError("Byte strings must be of equal length for XOR operation.")
    return bytes(x ^ y for x, y in zip(b1, b2))

def generate_challenge_indices(n, p):
    """Generate p distinct random indices between 0 and n-1."""
    indices = set()
    while len(indices) < p:
        indices.add(secrets.randbelow(n))
    return list(indices)

# ==========================================
# CORE CLASS: SECURE VAULT
# ==========================================
class SecureVault:
    def __init__(self, initial_keys=None):
        if initial_keys:
            self.keys = initial_keys
        else:
            # Generate n random keys of m bits
            self.keys = [secrets.token_bytes(KEY_SIZE_BYTES) for _ in range(N_KEYS)]

    def get_derived_key(self, indices: list) -> bytes:
        """
        Calculates k = K[c1] XOR K[c2] ... XOR K[cp]
        (Section IV-B)

        :param indices: List of indices to derive the key from (C1 or C2)
        :return: Derived key as bytes, k = K[c1] xor K[c2] xor ... xor K[cp]
        :rtype: bytes

        """
        derived_key = bytes(KEY_SIZE_BYTES) # Start with zeros
        for idx in indices:
            derived_key = xor_bytes(derived_key, self.keys[idx])
        return derived_key

    def update_vault(self, exchanged_data):
        """
        Updates the vault keys based on the session data.
        (Section IV-C)
        """
        # Serialize current vault for HMAC input
        vault_bytes = b''.join(self.keys)
        
        # Calculate h = HMAC(vault, data_exchanged)
        # Note: Paper says "key for HMAC is data exchanged".
        h = hmac.new(exchanged_data, vault_bytes, hashlib.sha256).digest()
        
        # Adjust h length to match Key Size (truncate or pad if necessary)
        # For simplicity, we assume SHA256 (32 bytes) matches or exceeds key needs.
        # The paper implies splitting vault into partitions and XORing with h.
        # We will XOR every key in the vault with h (trimmed to key size).
        h_trimmed = h[:KEY_SIZE_BYTES]
        
        new_keys = []
        for k in self.keys:
            new_keys.append(xor_bytes(k, h_trimmed))
        
        self.keys = new_keys
        cprint("b", "\n[Vault] Vault contents updated securely.")

# ==========================================
# ENTITIES (IoTEntity is a shared base class for encryption/decryption for both server and device)
# ==========================================

class IoTEntity:
    def encrypt(self, key, plaintext):
        """AES Encryption (CBC Mode with random IV)"""
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext # Prepend IV for transport

    def decrypt(self, key, ciphertext):
        """AES Decryption"""
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    
class IoTServer(IoTEntity):
    def __init__(self, vault: SecureVault):
        self.vault = vault
        self.device_db = {"device_001": "valid"} # Simulating DB
        self.temp_storage = {}

    def receive_M1_send_M2(self, m1):
        device_id = m1['device_id']
        session_id = m1['session_id']
        cprint('y', f"\n[Server] Received M1: Device = {device_id}, Session = {session_id}")
        
        if device_id in self.device_db:
            print(" ↳ Device ID recognized. Generating Challenge M2...")
            # Generate Challenge C1 and r1
            c1 = generate_challenge_indices(N_KEYS, P_INDICES)
            r1 = secrets.token_bytes(16)
            
            # Store state for later verification
            M2 = {'c1': c1, 'r1': r1}
            print(f" ↳ Generated and stored C1 and r1 for later verification (upon receiving M3).")
            print(f"[Server] Sending M2: {M2}")
            self.temp_storage = M2
            return M2
        else:
            raise Exception("Invalid Device ID")

    def receive_M3_send_M4(self, ciphertext_m3):
        cprint("y", "\n[Server] Received M3 (Encrypted)")
        
        # 1. Reconstruct k1 using stored C1
        k1 = self.vault.get_derived_key(self.temp_storage['c1'])
        
        # 2. Try to decrypt M3, if fails, attack is detected
        try:
            plaintext = self.decrypt(k1, ciphertext_m3)
            data = json.loads(plaintext.decode())
        except Exception as e:
            cprint("r", "[Server] Decryption failed. Attack detected.")
            return None
        
        print(" ↳ Decryption successful. Processing M3 data...")

        # 3. Verify r1, i.e. check if received_r1 matches stored_r1
        received_r1 = bytes.fromhex(data['r1'])
        if received_r1 != self.temp_storage['r1']:
            cprint("r", "[Server] Verification failed: r1 mismatch")
            return None
        
        print(" ↳ Device Authenticated successfully (received_r1 = stored_r1).")
        
        # 4. Process Device Challenge (C2)
        c2 = data['c2'] # challenge 2, list of indices
        r2 = bytes.fromhex(data['r2']) # Device's random
        t1 = bytes.fromhex(data['t1']) # Device's session key contribution
        
        # 5. Generate Response M4
        k2 = self.vault.get_derived_key(c2)
        print(f" ↳ k2 = K[c2_1] xor K[c2_2] xor ... xor K[c2_p] = {k2.hex()}")
        t2 = secrets.token_bytes(16) # Server's session key contribution
        
        payload = json.dumps({
            'r2': r2.hex(),
            't2': t2.hex()
        }).encode()
        
        m4 = self.encrypt(k2, payload)
        
        # Calculate final session key
        session_key = xor_bytes(t1, t2)
        print(f" ↳ Session Key (t1 xor t2) Generated: \033[95m{session_key.hex()[:10]}...\033[0m")
        print(" ↳ Sending M4 (Encrypted with k2): r2 and t2.")

        # Update Vault
        exchanged_data = self.temp_storage['r1'] + t1 + r2 + t2
        self.vault.update_vault(exchanged_data)
        
        return m4


class IoTDevice(IoTEntity):
    def __init__(self, vault: SecureVault, device_id: str):
        self.vault = vault
        self.device_id = device_id
        self.temp_storage = {}

    def send_M1(self):
        cprint('g', f"[Device] Initiating authentication")
        session_id = secrets.token_hex(4) # random 4-byte session ID
        print(f" ↳ Generated Session ID: {session_id}")
        M1 = {
            'device_id': self.device_id, 
            'session_id': session_id
            }
        print(f" ↳ Sending M1: {M1}")
        return M1

    def process_M2_send_M3(self, m2_data):
        cprint('g', f"\n[Device] Received M2")
        
        c1 = m2_data['c1']
        r1 = m2_data['r1']
        
        # 1. Derive k1 from C1
        k1 = self.vault.get_derived_key(c1)
        print(f" ↳ k1 = K[c1_1] xor K[c1_2] xor ... xor K[c1_p] = {k1.hex()}")
        
        # 2. Generate own challenge C2 and randoms
        c2 = generate_challenge_indices(N_KEYS, P_INDICES)
        r2 = secrets.token_bytes(16)
        t1 = secrets.token_bytes(16) # Device session key contribution
        
        # Store for M4 verification
        self.temp_storage = {'c2': c2, 'r2': r2, 't1': t1, 'r1': r1}
        print(f" ↳ Generated and stored C2, r2, t1, r1 for later verification (upon receiving M4).")
        
        # 3. Encrypt response (r1 || t1 || C2 || r2)
        # Using JSON for easy packing of mixed types (int list + bytes)
        payload = json.dumps({
            'r1': r1.hex(),
            't1': t1.hex(),
            'c2': c2,
            'r2': r2.hex()
        }).encode()
        
        m3 = self.encrypt(k1, payload)
        print(f" ↳ Sending M3 (Encrypted with k1): r1, t1, C2, r2.")
        return m3

    def process_M4(self, m4_ciphertext):
        cprint('g', "\n[Device] Received M4 (Encrypted)")
        
        # 1. Derive k2 from stored C2
        k2 = self.vault.get_derived_key(self.temp_storage['c2'])

        # 2. Decrypt
        try:
            plaintext = self.decrypt(k2, m4_ciphertext)
            data = json.loads(plaintext.decode())
        except:
            cprint('r', "[Device] Device decryption failed.")
            return
        print(" ↳ Decryption (using k2) successful. Processing M4 data...")

        # 3. Verify r2
        received_r2 = bytes.fromhex(data['r2'])
        if received_r2 != self.temp_storage['r2']:
            cprint('r', "[Device] Device verification failed: r2 mismatch")
            return

        print(" ↳ Server Authenticated successfully (received_r2 = stored_r2)")
        
        # 4. Generate Session Key
        t2 = bytes.fromhex(data['t2'])
        t1 = self.temp_storage['t1']
        session_key = xor_bytes(t1, t2)
        print(f" ↳ Session Key (t1 xor t2) Generated: \033[95m{session_key.hex()[:10]}...\033[0m")

        # Update Vault
        exchanged_data = self.temp_storage['r1'] + t1 + self.temp_storage['r2'] + t2
        self.vault.update_vault(exchanged_data)

# ==========================================
# MAIN EXECUTION FLOW
# ==========================================
if __name__ == "__main__":
    # 1. Setup Phase: Create identical vaults for Server and Device
    # In reality, this happens during manufacturing/provisioning
    initial_keys = [secrets.token_bytes(KEY_SIZE_BYTES) for _ in range(N_KEYS)]
    
    # Pass copies of the keys so objects don't share memory reference (simulate remote)
    server_vault = SecureVault(list(initial_keys))
    device_vault = SecureVault(list(initial_keys))

    # Create the entities (server and device)
    server = IoTServer(server_vault)
    device = IoTDevice(device_vault, "device_001")

    # 2. Authentication Flow
    # Step 1: Device sends Request (M1)
    m1 = device.send_M1()
    # Step 2: Server sends Challenge (M2)
    m2_data = server.receive_M1_send_M2(m1)
    # # Step 3: Device computes Response + New Challenge, sends M3
    m3_cipher = device.process_M2_send_M3(m2_data)
    # # Step 4: Server validates, sends Response M4, Updates Vault
    m4_cipher = server.receive_M3_send_M4(m3_cipher)
    # Step 5: Device validates, Updates Vault
    device.process_M4(m4_cipher)

    print("\n=== Verification of Vault Rotation ===")
    # Check if vaults rotated and are still synchronized
    print(f"Server Vault Key[0] prefix: {server.vault.keys[0].hex()[:8]}")
    print(f"Device Vault Key[0] prefix: {device.vault.keys[0].hex()[:8]}")
    
    if server.vault.keys == device.vault.keys:
        print("SUCCESS: Vaults are synchronized and rotated.")
    else:
        print("FAILURE: Vaults are out of sync.")
    
    # Verify they are different from initial
    if server.vault.keys[0] != initial_keys[0]:
         print("SUCCESS: Vaults differ from initial state.")