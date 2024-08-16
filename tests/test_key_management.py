import unittest
from encryption_module.key_management import store_key_in_kms

class TestKeyManagement(unittest.TestCase):
    def test_store_key_in_kms(self):
        key_alias = "test_alias"
        key_material = b"sample_key_material"
        key_id = store_key_in_kms(key_alias, key_material)
        self.assertIsNotNone(key_id)

if __name__ == '__main__':
    unittest.main()