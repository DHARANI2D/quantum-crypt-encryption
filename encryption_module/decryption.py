import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad
from pqcrypto.kem.kyber import Kyber512

def load_keys_from_json(file_path='encryption_module/key.json'):
    """Load the private key from the JSON file."""
    try:
        with open(file_path, 'r') as file:
            keys = json.load(file)
            # Load private key
            private_key = RSA.import_key(keys['private_key'])
            return private_key
    except Exception as e:
        print(f"Failed to load keys: {e}")
        return None

def decrypt_aes_key_with_kyber(encrypted_aes_key, private_key):
    """Decrypt the AES key using the Kyber private key."""
    kyber = Kyber512()
    # Decode the encrypted AES key from Base64
    encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
    # Decapsulate the key
    aes_key, _ = kyber.decapsulate(private_key, encrypted_aes_key_bytes)
    return aes_key

def decrypt_with_aes(encrypted_data, aes_key):
    """Decrypt data using AES decryption."""
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError) as e:
        raise ValueError("AES decryption failed. Check the encrypted data and AES key.") from e
    
    return plaintext.decode('utf-8')

def decrypt_with_chacha20(encrypted_data, chacha_key):
    """Decrypt data using ChaCha20."""
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def decrypt(encrypted_data_str, encrypted_aes_key_str):
    """Decrypt the encrypted data using the encrypted AES key."""
    private_key = load_keys_from_json()
    if private_key is None:
        raise ValueError("Failed to load private key.")
    
    # Decrypt AES key using Kyber
    aes_key = decrypt_aes_key_with_kyber(encrypted_aes_key_str, private_key)
    
    # Decode the JSON data
    encrypted_data = json.loads(encrypted_data_str)
    
    # Decrypt the data with AES
    decrypted_aes_data = decrypt_with_aes(encrypted_data, aes_key)

    # Decrypt the ChaCha20 encrypted data
    decrypted_data = decrypt_with_chacha20(decrypted_aes_data, aes_key)

    return decrypted_data

def main():
    # Replace with your actual Base64 encoded data
    encrypted_data_str = json.dumps({
        'iv': '...',  # Replace with your actual Base64 encoded IV
        'ciphertext': '...',  # Replace with your actual Base64 encoded ciphertext
        'nonce': '...'  # Replace with your actual Base64 encoded nonce from ChaCha20
    })
    encrypted_aes_key_str = '...'  # Replace with your actual Base64 encoded encrypted AES key

    decrypted_data = decrypt(encrypted_data_str, encrypted_aes_key_str)
    print(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    main()
