import json

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    
    response = {
        'statusCode': 200,
        'body': json.dumps('Hello from your Lambda function!')
    }
    return response
