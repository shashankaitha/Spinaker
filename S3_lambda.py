import logging
import os

import boto3
from botocore.exceptions import ClientError

SSECNF = 'ServerSideEncryptionConfigurationNotFoundError'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Create a custom logger
logger = logging.getLogger(__name__)

# Create handlers
c_handler = logging.StreamHandler()
c_handler.setLevel(logging.DEBUG)

# Create formatters and add it to handlers
c_format = logging.Formatter(LOG_FORMAT)
c_handler.setFormatter(c_format)

# Add handlers to the logger
logger.addHandler(c_handler)


#Add KMS ID
KMS_CMK_ID = 'ffab59b5-ba21-4b3c-98c5-06b3507ee6a6'


def retrieve_cmk(key: str):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.list_keys()
    except ClientError as e:
        logger.exception(e)
        return None, None

    done = False
    while not done:
        for cmk in response['Keys']:

            if cmk['KeyId'] == key:
                return cmk['KeyId'], cmk['KeyArn']

        if not response['Truncated']:
            logger.error('A CMK with the specified key id was not found')
            done = True
        else:
            try:
                response = kms_client.list_keys(Marker=response['NextMarker'])
            except ClientError as e:
                logger.exception(e)
                return None, None

    return None, None


def encrypt_buckets(kms_key: str):
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    logger.debug('KMS CMS KEY : ' + kms_key)
    for bucket in response['Buckets']:
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket['Name'])
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            logger.info('Bucket: %s, SSE Encryption Already Enabled' % (bucket['Name']))
        except ClientError as e:
            if e.response['Error']['Code'] == SSECNF:
                logger.info('Bucket: %s, no server-side encryption' %
                      (bucket['Name']))
                logger.info(' -'*5+' Encrypting S3 bucket SSE' +'-'*5)
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
                logger.info('Bucket: %s, Encrypted Successfully' % (bucket['Name']))
            else:
                logger.error("Bucket: %s, unexpected error: %s" % (bucket['Name'], e))


def lambda_handler(event, context):
    keyId, keyArn = retrieve_cmk(KMS_CMK_ID)

    if keyArn is not None:
        encrypt_buckets(keyArn)
    else:
        logger.error('KMS CMK key with description : %s does not exists'%
              KMS_CMK_ID)
