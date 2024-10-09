import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from pqcrypto.kem.kyber import Kyber512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def load_keys_from_json(file_path='encryption_module/key.json'):
    """Load the public key and AES key from the JSON file."""
    try:
        with open(file_path, 'r') as file:
            keys = json.load(file)
            kyber_public_key_base64 = keys.get('public_key', '')
            kyber_public_key = base64.b64decode(kyber_public_key_base64)
            aes_key_base64 = keys.get('aes_key', '')
            aes_key = base64.b64decode(aes_key_base64)
            if len(aes_key) not in {16, 24, 32}:
                raise ValueError("Invalid AES key length or format")
            return kyber_public_key, aes_key
    except Exception as e:
        print(f"Failed to load keys: {e}")
        return None, None

def encrypt_aes_key_with_kyber(aes_key, kyber_public_key):
    """Encrypt the AES key using the Kyber public key."""
    kyber = Kyber512()
    ciphertext, shared_secret = kyber.encapsulate(kyber_public_key)
    return base64.b64encode(ciphertext).decode('utf-8')

def encrypt_with_aes(plaintext, aes_key):
    """Encrypt data using AES encryption."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return {
        'iv': base64.b64encode(cipher.iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def encrypt_with_chacha20(plaintext, chacha_key):
    """Encrypt data using ChaCha20 encryption."""
    cipher = ChaCha20.new(key=chacha_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return {
        'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def derive_keys(password, salt):
    """Derive multiple keys from a password using PBKDF2."""
    aes_key = PBKDF2(password, salt, dkLen=32)  # AES key
    chacha_key = PBKDF2(password, salt, dkLen=32)  # ChaCha20 key
    return aes_key, chacha_key

def hybrid_encrypt(plaintext, password):
    """Encrypt data using multiple layers of encryption."""
    salt = get_random_bytes(16)  # Generate a random salt
    aes_key, chacha_key = derive_keys(password, salt)  # Derive keys

    # Encrypt the plaintext with AES
    aes_encrypted_data = encrypt_with_aes(plaintext, aes_key)

    # Encrypt the AES key with Kyber
    kyber_public_key, _ = load_keys_from_json()
    encrypted_aes_key = encrypt_aes_key_with_kyber(aes_key, kyber_public_key)

    # Encrypt the AES-encrypted data with ChaCha20
    chacha_encrypted_data = encrypt_with_chacha20(json.dumps(aes_encrypted_data), chacha_key)

    # Return combined encrypted data as JSON
    return json.dumps({
        'encrypted_data': chacha_encrypted_data,
        'encrypted_aes_key': encrypted_aes_key,
        'salt': base64.b64encode(salt).decode('utf-8')
    })

def encrypt(data, password):
    """Main encryption function."""
    encrypted_data = hybrid_encrypt(data, password)
    return encrypted_data

def main():
    data = "This is a test string for encryption."
    password = "securepassword123"  # Example password
    encrypted_data = encrypt(data, password)
    print(f"Encrypted data: {encrypted_data}")

if __name__ == "__main__":
    main()
