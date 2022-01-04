import logging
import os 

import boto3
from botocore.exceptions import ClientError

SSECNF = 'ServerSideEncryptionConfigurationNotFoundError'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Create a custom logger
logging.basicConfig(format=LOG_FORMAT)
logger = logging.getLogger()
logger.setLevel(logging.INFO)



def encrypt_buckets():
    s3 = boto3.client('s3')
    response = s3.list_buckets()
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
                                    'SSEAlgorithm': 'AES256'
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
    encrypt_buckets()
