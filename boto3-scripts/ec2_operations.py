#!/usr/bin/env python3
"""
Git-Captain Boto3 Script: EC2 Operations
Manage EC2 instances, retrieve metadata, and perform administrative tasks
"""

import boto3
import json
import sys
from datetime import datetime
from tabulate import tabulate

def list_instances(tag_filter=None, region='us-east-2'):
    """List all EC2 instances with optional tag filtering"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    try:
        filters = []
        if tag_filter:
            key, value = tag_filter.split('=')
            filters.append({'Name': f'tag:{key}', 'Values': [value]})
        
        response = ec2_client.describe_instances(Filters=filters)
        
        instances_data = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Extract instance details
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                state = instance['State']['Name']
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                public_ip = instance.get('PublicIpAddress', 'N/A')
                
                # Get Name tag
                name = 'N/A'
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                instances_data.append([
                    instance_id,
                    name,
                    instance_type,
                    state,
                    private_ip,
                    public_ip,
                    launch_time
                ])
        
        if not instances_data:
            print("No instances found")
            return []
        
        # Display as table
        headers = ['Instance ID', 'Name', 'Type', 'State', 'Private IP', 'Public IP', 'Launch Time']
        print("\n" + tabulate(instances_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal instances: {len(instances_data)}")
        
        return instances_data
        
    except Exception as e:
        print(f"✗ Error listing instances: {str(e)}")
        return []

def get_instance_metadata(instance_id, region='us-east-2'):
    """Get detailed metadata for a specific instance"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            print(f"Instance {instance_id} not found")
            return None
        
        instance = response['Reservations'][0]['Instances'][0]
        
        print(f"\n{'=' * 60}")
        print(f"Instance Metadata: {instance_id}")
        print('=' * 60)
        
        print(f"\nBasic Information:")
        print(f"  Instance ID:     {instance['InstanceId']}")
        print(f"  Instance Type:   {instance['InstanceType']}")
        print(f"  State:           {instance['State']['Name']}")
        print(f"  AMI ID:          {instance['ImageId']}")
        print(f"  Launch Time:     {instance['LaunchTime']}")
        
        print(f"\nNetwork Information:")
        print(f"  Private IP:      {instance.get('PrivateIpAddress', 'N/A')}")
        print(f"  Public IP:       {instance.get('PublicIpAddress', 'N/A')}")
        print(f"  VPC ID:          {instance.get('VpcId', 'N/A')}")
        print(f"  Subnet ID:       {instance.get('SubnetId', 'N/A')}")
        
        print(f"\nSecurity Groups:")
        for sg in instance.get('SecurityGroups', []):
            print(f"  - {sg['GroupName']} ({sg['GroupId']})")
        
        print(f"\nTags:")
        for tag in instance.get('Tags', []):
            print(f"  {tag['Key']}: {tag['Value']}")
        
        return instance
        
    except Exception as e:
        print(f"✗ Error getting instance metadata: {str(e)}")
        return None

def start_instance(instance_id, region='us-east-2'):
    """Start an EC2 instance"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    try:
        print(f"Starting instance {instance_id}...")
        response = ec2_client.start_instances(InstanceIds=[instance_id])
        print(f"✓ Instance {instance_id} is starting")
        print(f"  Current state: {response['StartingInstances'][0]['CurrentState']['Name']}")
        return True
    except Exception as e:
        print(f"✗ Error starting instance: {str(e)}")
        return False

def stop_instance(instance_id, region='us-east-2'):
    """Stop an EC2 instance"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    try:
        print(f"Stopping instance {instance_id}...")
        response = ec2_client.stop_instances(InstanceIds=[instance_id])
        print(f"✓ Instance {instance_id} is stopping")
        print(f"  Current state: {response['StoppingInstances'][0]['CurrentState']['Name']}")
        return True
    except Exception as e:
        print(f"✗ Error stopping instance: {str(e)}")
        return False

def create_key_pair(key_name, region='us-east-2'):
    """Create a new EC2 key pair"""
    ec2_client = boto3.client('ec2', region_name=region)
    
    try:
        print(f"Creating key pair: {key_name}...")
        response = ec2_client.create_key_pair(KeyName=key_name)
        
        # Save private key to file
        key_file = f"{key_name}.pem"
        with open(key_file, 'w') as f:
            f.write(response['KeyMaterial'])
        
        # Set proper permissions on Unix-like systems
        import os
        os.chmod(key_file, 0o400)
        
        print(f"✓ Key pair created: {key_name}")
        print(f"✓ Private key saved to: {key_file}")
        print(f"  Key Fingerprint: {response['KeyFingerprint']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error creating key pair: {str(e)}")
        return False

def get_auto_scaling_group_info(asg_name, region='us-east-2'):
    """Get Auto Scaling Group information"""
    asg_client = boto3.client('autoscaling', region_name=region)
    
    try:
        response = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )
        
        if not response['AutoScalingGroups']:
            print(f"Auto Scaling Group '{asg_name}' not found")
            return None
        
        asg = response['AutoScalingGroups'][0]
        
        print(f"\n{'=' * 60}")
        print(f"Auto Scaling Group: {asg_name}")
        print('=' * 60)
        
        print(f"\nCapacity:")
        print(f"  Min Size:        {asg['MinSize']}")
        print(f"  Max Size:        {asg['MaxSize']}")
        print(f"  Desired:         {asg['DesiredCapacity']}")
        print(f"  Current:         {len(asg['Instances'])}")
        
        print(f"\nInstances:")
        for instance in asg['Instances']:
            print(f"  - {instance['InstanceId']}: {instance['LifecycleState']} ({instance['HealthStatus']})")
        
        return asg
        
    except Exception as e:
        print(f"✗ Error getting ASG info: {str(e)}")
        return None

def main():
    """Main function for EC2 operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Git-Captain EC2 Operations')
    parser.add_argument('--region', default='us-east-2', help='AWS region')
    parser.add_argument('--list', action='store_true', help='List all EC2 instances')
    parser.add_argument('--filter', help='Filter instances by tag (e.g., Project=git-captain)')
    parser.add_argument('--metadata', help='Get metadata for instance ID')
    parser.add_argument('--start', help='Start instance by ID')
    parser.add_argument('--stop', help='Stop instance by ID')
    parser.add_argument('--create-key', help='Create new key pair')
    parser.add_argument('--asg', help='Get Auto Scaling Group info')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Git-Captain EC2 Operations")
    print("=" * 60)
    
    if args.list:
        list_instances(args.filter, args.region)
    
    if args.metadata:
        get_instance_metadata(args.metadata, args.region)
    
    if args.start:
        start_instance(args.start, args.region)
    
    if args.stop:
        stop_instance(args.stop, args.region)
    
    if args.create_key:
        create_key_pair(args.create_key, args.region)
    
    if args.asg:
        get_auto_scaling_group_info(args.asg, args.region)
    
    if not any([args.list, args.metadata, args.start, args.stop, args.create_key, args.asg]):
        parser.print_help()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Unexpected error: {str(e)}")
        sys.exit(1)
