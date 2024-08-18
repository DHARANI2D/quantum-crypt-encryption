import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad

def load_public_key_from_json(file_path='encryption_module/key.json'):
    """Load the public key and AES key from the JSON file."""
    try:
        with open(file_path, 'r') as file:
            keys = json.load(file)
            # Load public key
            public_key = RSA.import_key(keys['public_key'])
            # Load and decode AES key from Base64
            aes_key_base64 = keys.get('aes_key', '')
            aes_key = base64.b64decode(aes_key_base64)
            if len(aes_key) not in {16, 24, 32}:  # Ensure valid AES key length (128, 192, or 256 bits)
                raise ValueError("Invalid AES key length or format")
            return public_key, aes_key
    except Exception as e:
        print(f"Failed to load keys: {e}")
        return None, None

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """Encrypt the AES key using RSA public key."""
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_aes_key).decode('utf-8')

def hybrid_encrypt(plaintext, aes_key):
    """Encrypt data using AES encryption."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return {
        'encrypted_aes_key': base64.b64encode(aes_key).decode('utf-8'),
        'iv': base64.b64encode(cipher.iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def encrypt(data):
    """Encrypt data and return as JSON."""
    public_key, aes_key = load_public_key_from_json()
    if public_key is None or aes_key is None:
        return None

    # Encrypt data with AES
    encrypted_data = hybrid_encrypt(data, aes_key)

    # Encrypt AES key with RSA
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
    
    # Return encrypted data and encrypted AES key as JSON
    return json.dumps({
        'encrypted_data': encrypted_data,
        'encrypted_aes_key': encrypted_aes_key
    })

def main():
    data = "This is a test string for encryption."
    encrypted_data = encrypt(data)
    print(f"Encrypted data: {encrypted_data}")

if __name__ == "__main__":
    main()