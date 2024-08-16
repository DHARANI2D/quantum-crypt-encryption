import unittest
from encryption_module.encryption import encrypt_data

class TestEncryption(unittest.TestCase):
    def test_encryption(self):
        data = b"Test data"
        result = encrypt_data(data)
        self.assertIn('ciphertext', result)
        self.assertIn('shared_secret', result)

if __name__ == '__main__':
    unittest.main()