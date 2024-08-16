import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from aws_integration.config_manager import get_config

# Load configuration once and use it globally
config = get_config()

def get_s3_client():
    return boto3.client(
        's3',
        region_name=config.get('AWS_REGION'),
        aws_access_key_id=config.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=config.get('AWS_SECRET_ACCESS_KEY')
    )

def upload_to_s3(file_name, data):
    s3 = get_s3_client()
    
    try:
        response = s3.put_object(
            Bucket=config.get('AWS_S3_BUCKET_NAME'),
            Key=file_name,
            Body=data
        )
        print(f"Uploaded {file_name} to S3 bucket {config.get('AWS_S3_BUCKET_NAME')}")
        return response
    except NoCredentialsError:
        print("Credentials not available")
    except PartialCredentialsError:
        print("Incomplete credentials provided")
    except Exception as e:
        print(f"Failed to upload to S3: {str(e)}")

def list_s3_files():
    s3 = get_s3_client()
    
    try:
        bucket_name = config.get('AWS_S3_BUCKET_NAME')
        if not bucket_name:
            raise ValueError("AWS_S3_BUCKET_NAME is not set in the configuration.")
            
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            for item in response['Contents']:
                print(item['Key'])
        else:
            print("No files found in S3 bucket.")
    except NoCredentialsError:
        print("Credentials not available")
    except PartialCredentialsError:
        print("Incomplete credentials provided")
    except Exception as e:
        print(f"Failed to list files in S3: {str(e)}")

def download_from_s3(file_name):
    s3 = get_s3_client()
    
    try:
        response = s3.get_object(Bucket=config.get('AWS_S3_BUCKET_NAME'), Key=file_name)
        return response['Body'].read()
    except s3.exceptions.NoSuchKey:
        print(f"The file {file_name} does not exist in the bucket.")
    except NoCredentialsError:
        print("Credentials not available")
    except PartialCredentialsError:
        print("Incomplete credentials provided")
    except Exception as e:
        print(f"Failed to download from S3: {str(e)}")
