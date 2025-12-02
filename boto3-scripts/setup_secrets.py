#!/usr/bin/env python3
"""
Git-Captain Boto3 Script: AWS Secrets Manager Setup
This script reads the .env file and creates/updates secrets in AWS Secrets Manager
"""

import boto3
import json
import os
import sys
from pathlib import Path

def read_env_file(env_path='.env'):
    """Read .env file and parse key-value pairs"""
    env_vars = {}
    
    if not os.path.exists(env_path):
        print(f"Error: {env_path} file not found!")
        print("Please create a .env file with your GitHub OAuth credentials and configuration.")
        return None
    
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse key=value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
    
    return env_vars

def create_or_update_secret(secret_name, secret_dict, region='us-east-2'):
    """Create or update a secret in AWS Secrets Manager"""
    client = boto3.client('secretsmanager', region_name=region)
    secret_string = json.dumps(secret_dict, indent=2)
    
    try:
        # Try to retrieve the secret (to check if it exists)
        response = client.describe_secret(SecretId=secret_name)
        print(f"✓ Secret '{secret_name}' already exists. Updating...")
        
        # Update the secret
        client.update_secret(
            SecretId=secret_name,
            SecretString=secret_string
        )
        print(f"✓ Secret '{secret_name}' updated successfully!")
        
    except client.exceptions.ResourceNotFoundException:
        print(f"Creating new secret '{secret_name}'...")
        
        # Create the secret
        client.create_secret(
            Name=secret_name,
            Description='Git-Captain production environment variables',
            SecretString=secret_string,
            Tags=[
                {'Key': 'Project', 'Value': 'Git-Captain'},
                {'Key': 'Environment', 'Value': 'Production'},
                {'Key': 'ManagedBy', 'Value': 'boto3-script'}
            ]
        )
        print(f"✓ Secret '{secret_name}' created successfully!")
    
    except Exception as e:
        print(f"✗ Error managing secret: {str(e)}")
        return False
    
    return True

def main():
    """Main function to setup AWS Secrets Manager"""
    print("=" * 60)
    print("Git-Captain AWS Secrets Manager Setup")
    print("=" * 60)
    
    # Configuration
    secret_name = 'git-captain/prod'
    region = os.environ.get('AWS_REGION', 'us-east-2')
    env_file_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    
    # Read .env file
    print(f"\n[1/3] Reading environment variables from {env_file_path}...")
    env_vars = read_env_file(env_file_path)
    
    if not env_vars:
        sys.exit(1)
    
    print(f"✓ Found {len(env_vars)} environment variables")
    
    # Display keys (not values for security)
    print("\nEnvironment variables to store:")
    for key in env_vars.keys():
        print(f"  - {key}")
    
    # Confirm action
    print(f"\n[2/3] Storing secrets in AWS Secrets Manager...")
    print(f"Secret name: {secret_name}")
    print(f"Region: {region}")
    
    # Create or update secret
    success = create_or_update_secret(secret_name, env_vars, region)
    
    if not success:
        sys.exit(1)
    
    # Verify secret
    print(f"\n[3/3] Verifying secret...")
    try:
        client = boto3.client('secretsmanager', region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        stored_secrets = json.loads(response['SecretString'])
        
        print(f"✓ Verified {len(stored_secrets)} keys in secret")
        print("\n" + "=" * 60)
        print("✓ AWS Secrets Manager setup complete!")
        print("=" * 60)
        print(f"\nSecret ARN: {response['ARN']}")
        print(f"\nYour EC2 instances can now retrieve secrets using:")
        print(f"  aws secretsmanager get-secret-value --secret-id {secret_name} --region {region}")
        
    except Exception as e:
        print(f"✗ Error verifying secret: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Unexpected error: {str(e)}")
        sys.exit(1)
