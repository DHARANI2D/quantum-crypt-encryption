import time
import json
from encryption_module.encryption import encrypt
from encryption_module.decryption import decrypt

def benchmark(data: bytes):
    """Benchmark encryption and decryption."""
    start_time = time.time()
    
    # Encrypt the data
    encrypted_str = encrypt(data.decode())
    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"Encryption took {encryption_time} seconds.")
    
    # Parse the JSON string to extract encrypted data and AES key
    try:
        encrypted_data = json.loads(encrypted_str)
    except json.JSONDecodeError as e:
        print(f"Failed to parse encrypted data: {e}")
        return
    
    # Decrypt the data
    start_time = time.time()
    decrypted_data = decrypt(encrypted_data['encrypted_data'], encrypted_data['encrypted_aes_key'])
    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Decryption took {decryption_time} seconds.")
    
    return encryption_time, decryption_time
