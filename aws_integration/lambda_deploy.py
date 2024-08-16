import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from config_aws import AWS_REGION

def deploy_lambda(function_name, zip_file):
    lambda_client = boto3.client('lambda', region_name=AWS_REGION)
    
    try:
        with open(zip_file, 'rb') as f:
            zipped_code = f.read()

        response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zipped_code,
        )
        print(f"Deployed {function_name} to AWS Lambda")
        return response
    except FileNotFoundError:
        print(f"File {zip_file} not found")
    except NoCredentialsError:
        print("Credentials not available")
    except PartialCredentialsError:
        print("Incomplete credentials provided")
    except Exception as e:
        print(f"Failed to deploy Lambda function: {str(e)}")

def main():
    function_name = "DummyLambdaFunction"
    zip_file = "lambda_function.zip"
    deploy_lambda(function_name, zip_file)

if __name__ == "__main__":
    main()
