#!/usr/bin/env python3
"""
Git-Captain Boto3 Script: S3 Bucket Management
Create S3 buckets, upload static assets, configure lifecycle policies
"""

import boto3
import json
import os
import sys
from pathlib import Path
import mimetypes

def create_s3_bucket(bucket_name, region='us-east-2'):
    """Create an S3 bucket with encryption and versioning"""
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        # Check if bucket already exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            print(f"✓ Bucket '{bucket_name}' already exists")
            return True
        except:
            pass
        
        # Create bucket
        print(f"Creating S3 bucket: {bucket_name}...")
        
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # Enable encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )
        
        # Block public access
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Add tags
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                'TagSet': [
                    {'Key': 'Project', 'Value': 'Git-Captain'},
                    {'Key': 'ManagedBy', 'Value': 'boto3-script'}
                ]
            }
        )
        
        print(f"✓ Bucket '{bucket_name}' created successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Error creating bucket: {str(e)}")
        return False

def upload_directory_to_s3(local_directory, bucket_name, s3_prefix=''):
    """Upload a directory to S3 bucket"""
    s3_client = boto3.client('s3')
    uploaded_count = 0
    
    print(f"\nUploading files from '{local_directory}' to s3://{bucket_name}/{s3_prefix}")
    
    for root, dirs, files in os.walk(local_directory):
        for file in files:
            local_path = os.path.join(root, file)
            relative_path = os.path.relpath(local_path, local_directory)
            s3_key = os.path.join(s3_prefix, relative_path).replace('\\', '/')
            
            # Determine content type
            content_type, _ = mimetypes.guess_type(local_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            try:
                extra_args = {'ContentType': content_type}
                
                # Set cache control for static assets
                if content_type.startswith(('text/css', 'application/javascript', 'image/')):
                    extra_args['CacheControl'] = 'max-age=86400'
                
                s3_client.upload_file(
                    local_path,
                    bucket_name,
                    s3_key,
                    ExtraArgs=extra_args
                )
                
                print(f"  ✓ Uploaded: {s3_key} ({content_type})")
                uploaded_count += 1
                
            except Exception as e:
                print(f"  ✗ Failed to upload {relative_path}: {str(e)}")
    
    print(f"\n✓ Uploaded {uploaded_count} files")
    return uploaded_count

def set_lifecycle_policy(bucket_name):
    """Set lifecycle policy to expire old logs"""
    s3_client = boto3.client('s3')
    
    lifecycle_policy = {
        'Rules': [
            {
                'Id': 'DeleteOldLogs',
                'Status': 'Enabled',
                'Prefix': 'logs/',
                'Expiration': {'Days': 90}
            },
            {
                'Id': 'TransitionOldBackups',
                'Status': 'Enabled',
                'Prefix': 'backups/',
                'Transitions': [
                    {
                        'Days': 30,
                        'StorageClass': 'STANDARD_IA'
                    },
                    {
                        'Days': 90,
                        'StorageClass': 'GLACIER'
                    }
                ]
            }
        ]
    }
    
    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_policy
        )
        print(f"✓ Lifecycle policy configured for '{bucket_name}'")
        return True
    except Exception as e:
        print(f"✗ Error setting lifecycle policy: {str(e)}")
        return False

def list_bucket_contents(bucket_name, prefix=''):
    """List contents of an S3 bucket"""
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix,
            MaxKeys=50
        )
        
        if 'Contents' not in response:
            print(f"Bucket '{bucket_name}' is empty")
            return []
        
        print(f"\nContents of s3://{bucket_name}/{prefix}:")
        for obj in response['Contents']:
            size_mb = obj['Size'] / (1024 * 1024)
            print(f"  - {obj['Key']} ({size_mb:.2f} MB)")
        
        return response['Contents']
        
    except Exception as e:
        print(f"✗ Error listing bucket: {str(e)}")
        return []

def main():
    """Main function for S3 bucket management"""
    print("=" * 60)
    print("Git-Captain S3 Bucket Management")
    print("=" * 60)
    
    region = os.environ.get('AWS_REGION', 'us-east-2')
    
    # Define buckets
    buckets = {
        'static-assets': 'git-captain-static-assets',
        'logs': 'git-captain-logs-bucket',
        'ssl-certs': 'git-captain-ssl-certs'
    }
    
    # Create buckets
    print("\n[1/4] Creating S3 buckets...")
    for purpose, bucket_name in buckets.items():
        print(f"\n{purpose.upper()} Bucket:")
        create_s3_bucket(bucket_name, region)
    
    # Set lifecycle policies
    print("\n[2/4] Configuring lifecycle policies...")
    set_lifecycle_policy(buckets['logs'])
    
    # Upload static assets
    print("\n[3/4] Uploading static assets...")
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'public')
    
    if os.path.exists(static_dir):
        upload_directory_to_s3(static_dir, buckets['static-assets'], 'public')
    else:
        print(f"⚠ Static directory not found: {static_dir}")
    
    # List bucket contents
    print("\n[4/4] Verifying uploads...")
    for purpose, bucket_name in buckets.items():
        try:
            list_bucket_contents(bucket_name)
        except Exception as e:
            print(f"⚠ Could not list {bucket_name}: {str(e)}")
    
    print("\n" + "=" * 60)
    print("✓ S3 Bucket Management Complete!")
    print("=" * 60)
    print("\nBucket URLs:")
    for purpose, bucket_name in buckets.items():
        print(f"  {purpose}: s3://{bucket_name}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Unexpected error: {str(e)}")
        sys.exit(1)
