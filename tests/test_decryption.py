import unittest
from encryption_module.decryption import decrypt_data

class TestDecryption(unittest.TestCase):
    def test_decryption(self):
        # Use the output from your encryption test
        ciphertext = "encrypted_string"
        secret_key = "secret_key_string"
        result = decrypt_data(ciphertext, secret_key)
        self.assertIsInstance(result, bytes)

if __name__ == '__main__':
    unittest.main()