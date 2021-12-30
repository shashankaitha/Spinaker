import boto3
from botocore.exceptions import ClientError

SSECNF = 'ServerSideEncryptionConfigurationNotFoundError'

#Add KMS ID
KMS_CMK_ID = '12ba95-6930-431c-afa4-49757a4fd657'


def retrieve_cmk(key: str):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.list_keys()
    except ClientError as e:
        print(e)
        return None, None

    done = False
    while not done:
        for cmk in response['Keys']:

            if cmk['KeyId'] == key:
                return cmk['KeyId'], cmk['KeyArn']

        if not response['Truncated']:
            print('A CMK with the specified description was not found')
            done = True
        else:
            try:
                response = kms_client.list_keys(Marker=response['NextMarker'])
            except ClientError as e:
                print(e)
                return None, None

    return None, None


def encrypt_buckets(kms_key: str):
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    print(kms_key)
    for bucket in response['Buckets']:
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket['Name'])
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            print('Bucket: %s, SSE Encryption Already Enabled' % (bucket['Name']))
        except ClientError as e:
            if e.response['Error']['Code'] == SSECNF:
                print('Bucket: %s, no server-side encryption' %
                      (bucket['Name']))
                print(' -'*5+' Encrypting S3 bucket SSE' +'-'*5)
                s3.put_bucket_encryption(
                    Bucket=bucket['Name'],
                    ServerSideEncryptionConfiguration={
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'aws:kms',
                                    'KMSMasterKeyID': kms_key
                                }
                            },
                        ]
                    }
                )
                enc = s3.get_bucket_encryption(Bucket=bucket['Name'])
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                print('Bucket: %s, Encrypted Successfully' % (bucket['Name']))
            else:
                print("Bucket: %s, unexpected error: %s" % (bucket['Name'], e))


if __name__ == '__main__':
    keyId, keyArn = retrieve_cmk(KMS_CMK_ID)

    if keyArn is not None:
        encrypt_buckets(keyArn)
    else:
        print('KMS CMK key with description : %s does not exists'%
              KMS_CMK_ID)
