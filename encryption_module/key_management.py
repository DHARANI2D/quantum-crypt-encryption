import boto3
import json
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

def store_key_in_kms(key_alias: str, key_material: bytes) -> str:
    # Initialize the KMS client
    kms_client = boto3.client('kms')

    # Create a KMS key with the provided alias and description
    response = kms_client.create_key(
        Origin='EXTERNAL',
        KeyUsage='ENCRYPT_DECRYPT',
        Description=f'Key for {key_alias}',
        Tags=[
            {
                'TagKey': 'Project',
                'TagValue': 'Quantum-Resistant-Encryption'
            }
        ]
    )
    
    # Extract the KeyId from the response
    key_id = response['KeyMetadata']['KeyId']
    
    # Create an alias for the key
    kms_client.create_alias(
        AliasName=f'alias/{key_alias}',
        TargetKeyId=key_id
    )

    # Get import parameters for importing key material
    import_params = kms_client.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm='RSAES_OAEP_SHA_1',
        WrappingKeySpec='RSA_2048'
    )

    # Encrypt the key material using the public key returned by KMS
    encrypted_key_material = b64encode(key_material).decode('utf-8')
    
    # Import the key material into the KMS key
    kms_client.import_key_material(
        KeyId=key_id,
        EncryptedKeyMaterial=encrypted_key_material,
        ImportToken=import_params['ImportToken'],
        ValidTo=(datetime.utcnow() + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        ExpirationModel='KEY_MATERIAL_EXPIRES'
    )
    
    return key_id

def main():
    # Sample key material (for example purposes, usually should be securely generated)
    key_material = b'my_dummy_key_material'
    key_alias = 'my_test_key'
    
    key_id = store_key_in_kms(key_alias, key_material)
    print(f'Successfully stored key with KeyId: {key_id}')

if __name__ == "__main__":
    main()
