# Secure Vault Authentication Proof of Concept

This repository contains a Python implementation of a symmetric mutual authentication protocol. As seen in Shah, T. and Venkatesan, S. (2018). "Authentication of IoT Device and IoT Server using Secure Vaults". It uses a synchronized "vault" of random keys to derive temporary session keys. After every session, the vault is mathematically mutated to ensure forward secrecy.

## System Configuration

The system relies on three constants defined at the top of the script:

* `N_KEYS`: The number of distinct keys stored in the vault (default: 128).
* `KEY_SIZE_BITS`: The bit-length of every key in the vault (default: 128-bit).
* `P_INDICES`: The number of keys selected and combined to create a single encryption key (default: 10).

## Code Structure

### Class: SecureVault

This class manages the core secret data. It simulates a secure storage element found in IoT hardware.

* **Initialization**: It creates a list of random byte strings or uses the `initial_keys` parameter. In a real deployment, these would be pre-shared secrets burned into the device and server.
* **Key Derivation (`get_derived_key`)**: This is the core logic. It accepts a list of integers (indices). It fetches the keys at those positions and XORs them all together.
* **Vault Rotation (`update_vault`)**: This method changes the stored keys. It takes the public data exchanged during the session, hashes it, and XORs the result against every key in the vault. This ensures the vault state changes after every session.

### Class: IoTEntity

This is a base helper class inherited by both the Server and the Device. It handles the low-level cryptography.

* **Encryption**: Uses AES-128 in CBC mode. It automatically generates a random IV (Initialization Vector) and handles PKCS7 padding to ensure the data fits the block size.
* **Decryption**: Reverses the process, removing padding and returning raw bytes.

### Class: IoTServer

This class represents the backend or gateway authority. It maintains a database of valid device IDs.

* **M1 -> M2** `receive_M1_send_M2`: It receives a connection request. If the device ID is valid, it generates "Challenge 1" (a list of random indices pointing to keys in the vault) and a random nonce.
* **M3 -> M4** `receive_M3_send_M4`: It receives an encrypted payload. To read it, it must reconstruct the decryption key using the indices it sent in M2. If decryption works and the nonce matches, it authenticates the device. It then generates "Challenge 2" (its own contribution to the session key) and encrypts the final response.

### Class: IoTDevice

This class represents the client or sensor.

* **M1** `send_M1`: It initiates the connection with a clear-text Hello message.
* **M2 -> M3** `process_M2_send_M3`: It receives the server's challenge indices. It uses its local `SecureVault` to derive the encryption key. It then encrypts its own challenge (Challenge 2) and session secrets to send back to the server.
* **M4** `process_M4`: It decrypts the final server response. It verifies that the server successfully derived the key from Challenge 2.

## How Vault Rotation Works

The unique feature of this code is the `update_vault` method called at the end of the `IoTServer` and `IoTDevice` workflows.

1. **Input**: The method takes all public nonces (random numbers) exchanged during the handshake.
2. **HMAC**: It creates a SHA-256 HMAC of the vault's current state using the exchanged data as the key.
3. **Mutation**: It modifies every single key in the vault using the output of the HMAC.
