#!/usr/bin/env python3
import boto3
import sys
import time

def get_command_output(command_id, instance_id, region='us-east-2'):
    ssm = boto3.client('ssm', region_name=region)
    
    # Wait a bit for command to complete
    time.sleep(2)
    
    try:
        response = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        
        print(f"Status: {response['Status']}")
        print(f"\n{'='*60}")
        print("STANDARD OUTPUT:")
        print('='*60)
        print(response.get('StandardOutputContent', ''))
        
        if response.get('StandardErrorContent'):
            print(f"\n{'='*60}")
            print("STANDARD ERROR:")
            print('='*60)
            print(response['StandardErrorContent'])
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python get-ssm-output.py <command-id> <instance-id>")
        sys.exit(1)
    
    get_command_output(sys.argv[1], sys.argv[2])
