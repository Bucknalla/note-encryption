from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def decrypt_data(private_key_path: str, payload: dict) -> bytes:
    """
    Decrypts data that was encrypted using ECDH key exchange and AES-256-CBC encryption.

    Args:
        private_key_path (str): Path to the private key PEM file used for ECDH
        payload (dict): Dictionary containing the encrypted data from Notehub event:
            - key: Base64 encoded ephemeral public key
            - data: Base64 encoded encrypted data

    Returns:
        bytes: The decrypted data with padding removed

    Raises:
        Various cryptography exceptions if decryption fails
    """
    # 0. Check if payload is valid
    if not payload or not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    
    # 1. Check if algorithm is supported
    if payload['alg'] != 'secp384r1-aes256cbc':
        raise ValueError("Unsupported algorithm")
    
    # 3. Decode the base64 ephemeral public key
    public_key_bytes = base64.b64decode(payload['key'])
    peer_public_key = serialization.load_der_public_key(public_key_bytes)

    # 4. Load private key and derive shared secret
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    print(f"Shared secret: {shared_secret.hex()}")

    # 5. Hash the shared secret to get AES key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    aes_key = digest.finalize()
    print(f"AES key: {aes_key.hex()}")

    # 6. Decode the encrypted data
    encrypted_data = base64.b64decode(payload['data'])
    print(f"Encrypted data: {encrypted_data.hex()}")

    # 7. Decrypt with zero IV
    cipher = Cipher(algorithms.AES256(aes_key), modes.CBC(b'\x00' * 16))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # 8. Remove padding if present
    try:
        padding_length = decrypted[-1]
        if padding_length <= 16:
            decrypted = decrypted[:-padding_length]
    except:
        pass

    return decrypted