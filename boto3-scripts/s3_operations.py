#!/usr/bin/env python3
"""
S3 Operations Script - Boto3 Demo
Academic Project: AWS Infrastructure Management

This script demonstrates:
1. Creating an S3 bucket
2. Uploading files to S3
3. Listing objects in a bucket
4. Downloading files from S3
5. Deleting objects and buckets

Author: Git-Captain Team
Date: December 2025
"""

import boto3
import os
import sys
from datetime import datetime
from botocore.exceptions import ClientError

# Initialize S3 client
s3_client = boto3.client('s3')
s3_resource = boto3.resource('s3')


def create_bucket(bucket_name, region='us-east-2'):
    """
    Create an S3 bucket in a specified region
    
    Args:
        bucket_name (str): Name of bucket to create
        region (str): AWS region for bucket
    
    Returns:
        bool: True if bucket created, False otherwise
    """
    try:
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"✓ Bucket '{bucket_name}' created successfully in {region}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(f"✓ Bucket '{bucket_name}' already exists and is owned by you")
            return True
        elif e.response['Error']['Code'] == 'BucketAlreadyExists':
            print(f"✗ Bucket name '{bucket_name}' already taken by another account")
            return False
        else:
            print(f"✗ Error creating bucket: {e}")
            return False


def upload_file(file_path, bucket_name, object_name=None):
    """
    Upload a file to an S3 bucket
    
    Args:
        file_path (str): Path to file to upload
        bucket_name (str): Destination bucket name
        object_name (str): S3 object name (default: file_path basename)
    
    Returns:
        bool: True if file uploaded, False otherwise
    """
    if object_name is None:
        object_name = os.path.basename(file_path)
    
    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        print(f"✓ File '{file_path}' uploaded to '{bucket_name}/{object_name}'")
        return True
    except FileNotFoundError:
        print(f"✗ File '{file_path}' not found")
        return False
    except ClientError as e:
        print(f"✗ Error uploading file: {e}")
        return False


def upload_string(content, bucket_name, object_name):
    """
    Upload string content directly to S3
    
    Args:
        content (str): String content to upload
        bucket_name (str): Destination bucket name
        object_name (str): S3 object name
    
    Returns:
        bool: True if uploaded, False otherwise
    """
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=object_name,
            Body=content.encode('utf-8'),
            ContentType='text/plain'
        )
        print(f"✓ Content uploaded to '{bucket_name}/{object_name}'")
        return True
    except ClientError as e:
        print(f"✗ Error uploading content: {e}")
        return False


def list_objects(bucket_name, prefix=''):
    """
    List all objects in an S3 bucket
    
    Args:
        bucket_name (str): Bucket name to list
        prefix (str): Filter objects by prefix
    
    Returns:
        list: List of object keys
    """
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        
        if 'Contents' not in response:
            print(f"No objects found in '{bucket_name}' with prefix '{prefix}'")
            return []
        
        objects = [obj['Key'] for obj in response['Contents']]
        print(f"\n✓ Objects in '{bucket_name}':")
        for obj in objects:
            print(f"  - {obj}")
        
        return objects
    except ClientError as e:
        print(f"✗ Error listing objects: {e}")
        return []


def download_file(bucket_name, object_name, file_path):
    """
    Download a file from S3
    
    Args:
        bucket_name (str): Source bucket name
        object_name (str): S3 object name
        file_path (str): Local path to save file
    
    Returns:
        bool: True if downloaded, False otherwise
    """
    try:
        s3_client.download_file(bucket_name, object_name, file_path)
        print(f"✓ File '{object_name}' downloaded to '{file_path}'")
        return True
    except ClientError as e:
        print(f"✗ Error downloading file: {e}")
        return False


def delete_object(bucket_name, object_name):
    """
    Delete an object from S3 bucket
    
    Args:
        bucket_name (str): Bucket name
        object_name (str): Object key to delete
    
    Returns:
        bool: True if deleted, False otherwise
    """
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=object_name)
        print(f"✓ Object '{object_name}' deleted from '{bucket_name}'")
        return True
    except ClientError as e:
        print(f"✗ Error deleting object: {e}")
        return False


def delete_bucket(bucket_name):
    """
    Delete an S3 bucket (must be empty)
    
    Args:
        bucket_name (str): Bucket name to delete
    
    Returns:
        bool: True if deleted, False otherwise
    """
    try:
        # First, delete all objects in bucket
        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.all().delete()
        
        # Then delete the bucket
        bucket.delete()
        print(f"✓ Bucket '{bucket_name}' and all contents deleted")
        return True
    except ClientError as e:
        print(f"✗ Error deleting bucket: {e}")
        return False


def get_bucket_info(bucket_name):
    """
    Get information about an S3 bucket
    
    Args:
        bucket_name (str): Bucket name
    """
    try:
        # Get bucket location
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = location['LocationConstraint'] or 'us-east-1'
        
        # Get bucket size
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            total_size = sum(obj['Size'] for obj in response['Contents'])
            object_count = len(response['Contents'])
        else:
            total_size = 0
            object_count = 0
        
        print(f"\n✓ Bucket Information:")
        print(f"  Name: {bucket_name}")
        print(f"  Region: {region}")
        print(f"  Objects: {object_count}")
        print(f"  Total Size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
        
    except ClientError as e:
        print(f"✗ Error getting bucket info: {e}")


def demo_s3_operations():
    """
    Demonstrate all S3 operations
    """
    print("=" * 60)
    print("Git-Captain S3 Operations Demo")
    print("=" * 60)
    
    # Generate unique bucket name
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bucket_name = f"git-captain-demo-{timestamp}"
    region = 'us-east-2'
    
    # 1. Create bucket
    print("\n1. Creating S3 Bucket...")
    if not create_bucket(bucket_name, region):
        print("Failed to create bucket. Exiting...")
        return
    
    # 2. Upload sample files
    print("\n2. Uploading Files...")
    
    # Upload string content
    sample_content = f"""
    Git-Captain S3 Demo File
    Created: {datetime.now().isoformat()}
    
    This file demonstrates S3 upload functionality using Boto3.
    """
    upload_string(sample_content, bucket_name, 'uploads/demo.txt')
    
    # Upload README if it exists
    readme_path = os.path.join(os.path.dirname(__file__), '..', 'README.md')
    if os.path.exists(readme_path):
        upload_file(readme_path, bucket_name, 'uploads/README.md')
    
    # Upload this script
    script_path = __file__
    upload_file(script_path, bucket_name, 'scripts/s3_operations.py')
    
    # 3. List objects
    print("\n3. Listing Bucket Contents...")
    objects = list_objects(bucket_name)
    
    # 4. Get bucket info
    print("\n4. Getting Bucket Information...")
    get_bucket_info(bucket_name)
    
    # 5. Download a file
    print("\n5. Downloading File...")
    download_file(bucket_name, 'uploads/demo.txt', '/tmp/downloaded-demo.txt')
    
    # 6. Cleanup (optional)
    print("\n6. Cleanup Options:")
    print(f"To delete this demo bucket, run:")
    print(f"  python -c \"from s3_operations import delete_bucket; delete_bucket('{bucket_name}')\"")
    
    print("\n" + "=" * 60)
    print(f"✓ Demo completed! Bucket: {bucket_name}")
    print("=" * 60)


if __name__ == '__main__':
    try:
        demo_s3_operations()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)
