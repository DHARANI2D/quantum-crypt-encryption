import time
from encryption_module.encryption import encrypt
from encryption_module.decryption import decrypt

def benchmark(data: bytes):
    """Benchmark encryption and decryption."""
    start_time = time.time()
    encrypted = encrypt(data.decode())
    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"Encryption took {encryption_time} seconds.")
    
    start_time = time.time()
    decrypted = decrypt(encrypted)
    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Decryption took {decryption_time} seconds.")
    
    return encryption_time, decryption_time
