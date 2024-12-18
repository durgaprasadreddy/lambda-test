import boto3
import json
import base64
from botocore.exceptions import ClientError

# Initialize S3 client
s3 = boto3.client('s3')
guardduty = boto3.client('guardduty')

# Define the quarantine bucket name
QUARANTINE_BUCKET = "quarantine-bucket"

def lambda_handler(event, context):
    """
    Handles GuardDuty findings for malware in S3 and moves infected files to quarantine bucket.
    """
    try:
        print("Received Event: ", json.dumps(event, indent=2))

        # Extract GuardDuty finding details
        for record in event['Records']:
            finding = json.loads(record['body'])
            print("GuardDuty Finding: ", json.dumps(finding, indent=2))

            # Check if finding type is malware detection
            if finding['detail']['type'] == "Software and Configuration Checks/Malware":
                bucket_name = finding['detail']['resource']['resourceDetails']['s3BucketDetails'][0]['name']
                object_key = finding['detail']['resource']['resourceDetails']['s3ObjectDetails']['key']

                print(f"Malware detected in file: {object_key} in bucket: {bucket_name}")

                # Copy the malware file to the quarantine bucket
                copy_to_quarantine(bucket_name, object_key)

        return {
            "statusCode": 200,
            "body": "Processing completed successfully."
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            "statusCode": 500,
            "body": f"Error: {e}"
        }


def copy_to_quarantine(source_bucket, object_key):
    """
    Copies the infected file to the quarantine bucket.
    """
    try:
        # Copy the file to the quarantine bucket
        s3.copy_object(
            Bucket=QUARANTINE_BUCKET,
            CopySource={'Bucket': source_bucket, 'Key': object_key},
            Key=object_key
        )
        print(f"File quarantined: {object_key} in bucket: {QUARANTINE_BUCKET}")

        # Delete the file from the source bucket (optional, if desired)
        s3.delete_object(Bucket=source_bucket, Key=object_key)
        print(f"File deleted from source bucket: {source_bucket}")

    except ClientError as e:
        print(f"Error quarantining file: {e}")
        raise
