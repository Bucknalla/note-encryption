from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64

def encrypt_message(public_key_path, message):
    # 1. Load recipient's public key
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    
    # 2. Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # 3. Perform ECDH key exchange
    shared_secret = ephemeral_private_key.exchange(
        ec.ECDH(), 
        public_key
    )
    
    # 4. Derive AES key from shared secret
    aes_key = hashes.Hash(hashes.SHA256())
    aes_key.update(shared_secret)
    aes_key = aes_key.finalize()[:32]  # First 32 bytes for AES-256
    
    # 5. Generate IV (Initialization Vector)
    iv = os.urandom(16)
    
    # 6. Encrypt message with AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad message to block size
    padded_message = message + b'\0' * (16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # 7. Prepare output
    return {
        'ephemeral_public_key': base64.b64encode(
            ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

# Usage example
message = b"Secret message"
encrypted = encrypt_message('keys/publicKey.pem', message)
print(encrypted)