import json
import os

CONFIG_FILE = 'aws_integration/config_aws.json'

def get_config():
    """Load configuration from the config file."""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found.")
    with open(CONFIG_FILE, 'r') as file:
        return json.load(file)

def update_config(aws_access_key_id=None, aws_secret_access_key=None, aws_region=None, aws_s3_bucket_name=None):
    """Update configuration with provided values."""
    config = get_config()

    if aws_access_key_id is not None:
        config['AWS_ACCESS_KEY_ID'] = aws_access_key_id
    if aws_secret_access_key is not None:
        config['AWS_SECRET_ACCESS_KEY'] = aws_secret_access_key
    if aws_region is not None:
        config['AWS_REGION'] = aws_region
    if aws_s3_bucket_name is not None:
        config['AWS_S3_BUCKET_NAME'] = aws_s3_bucket_name

    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)
