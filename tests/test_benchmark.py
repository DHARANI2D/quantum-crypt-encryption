import unittest
from performance_benchmark.benchmark import benchmark_encryption

class TestBenchmark(unittest.TestCase):
    def test_benchmark_encryption(self):
        data = b"Test data"
        encryption_time, decryption_time = benchmark_encryption(data)
        self.assertGreater(encryption_time, 0)
        self.assertGreater(decryption_time, 0)

if __name__ == '__main__':
    unittest.main()