import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64

def load_keys_from_json(file_path='encryption_module/key.json'):
    """Load the private key and AES key from the JSON file."""
    try:
        with open(file_path, 'r') as file:
            keys = json.load(file)
            # Load private key
            private_key = RSA.import_key(keys['private_key'])
            # Load and decode AES key from Base64
            aes_key_base64 = keys.get('aes_key', '')
            aes_key = base64.b64decode(aes_key_base64)
            if len(aes_key) not in {16, 24, 32}:  # Ensure valid AES key length (128, 192, or 256 bits)
                raise ValueError("Invalid AES key length or format")
            return private_key, aes_key
    except Exception as e:
        print(f"Failed to load keys: {e}")
        return None, None

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """Decrypt the AES key using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    try:
        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    except ValueError as e:
        raise ValueError("RSA decryption failed. Check the encrypted AES key and RSA private key.") from e
    
    return aes_key

def hybrid_decrypt(encrypted_data, aes_key):
    """Decrypt data using AES decryption."""
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError) as e:
        raise ValueError("AES decryption failed. Check the encrypted data and AES key.") from e
    
    return plaintext.decode('utf-8')

def decrypt(encrypted_data_str, encrypted_aes_key_str):
    """Decrypt the encrypted data using the encrypted AES key."""
    private_key,_ = load_keys_from_json()
    if private_key is None:
        raise ValueError("Failed to load private key.")
    
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key_str, private_key)
    
    # encrypted_data = json.loads(encrypted_data_str)
    decrypted_data = hybrid_decrypt(encrypted_data_str, aes_key)
    
    return decrypted_data

def main():
    encrypted_data_str = json.dumps({
        'iv': '...',  # Replace with your actual Base64 encoded IV
        'ciphertext': '...'  # Replace with your actual Base64 encoded ciphertext
    })
    encrypted_aes_key_str = '...'  # Replace with your actual Base64 encoded encrypted AES key
    
    decrypted_data = decrypt(encrypted_data_str, encrypted_aes_key_str)
    print(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    main()