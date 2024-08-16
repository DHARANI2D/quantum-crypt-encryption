import unittest
from aws_integration.s3_upload import upload_to_s3

class TestS3Upload(unittest.TestCase):
    def test_upload_to_s3(self):
        bucket_name = "my-test-bucket"
        file_name = "test_file.txt"
        data = b"Sample data"
        upload_to_s3(bucket_name, file_name, data)
        # Check the S3 bucket manually to verify upload.

if __name__ == '__main__':
    unittest.main()