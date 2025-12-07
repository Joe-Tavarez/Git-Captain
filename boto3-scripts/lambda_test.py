#!/usr/bin/env python3
"""
Git-Captain Boto3 Script: Lambda Testing and Invocation
Manually invoke Lambda functions and test S3 event triggers
"""

import boto3
import json
import sys
from datetime import datetime

def invoke_lambda(function_name, payload=None, region='us-east-2'):
    """Invoke a Lambda function with optional payload"""
    lambda_client = boto3.client('lambda', region_name=region)
    
    if payload is None:
        payload = {}
    
    try:
        print(f"Invoking Lambda function: {function_name}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        # Parse response
        status_code = response['StatusCode']
        response_payload = json.loads(response['Payload'].read())
        
        print(f"\n✓ Lambda invoked successfully!")
        print(f"  Status Code: {status_code}")
        print(f"  Response:")
        print(json.dumps(response_payload, indent=2))
        
        return response_payload
        
    except Exception as e:
        print(f"✗ Error invoking Lambda: {str(e)}")
        return None

def test_s3_upload_logger(bucket_name, object_key, region='us-east-2'):
    """Test the S3 upload logger Lambda with a simulated S3 event"""
    
    # Create a sample S3 event
    s3_event = {
        'Records': [
            {
                'eventVersion': '2.1',
                'eventSource': 'aws:s3',
                'awsRegion': region,
                'eventTime': datetime.utcnow().isoformat() + 'Z',
                'eventName': 's3:ObjectCreated:Put',
                's3': {
                    'bucket': {
                        'name': bucket_name,
                        'arn': f'arn:aws:s3:::{bucket_name}'
                    },
                    'object': {
                        'key': object_key,
                        'size': 1024,
                        'eTag': 'test-etag'
                    }
                }
            }
        ]
    }
    
    function_name = 'git-captain-prod-s3-upload-logger'
    
    print("=" * 60)
    print("Testing S3 Upload Logger Lambda")
    print("=" * 60)
    print(f"\nSimulating S3 upload event:")
    print(f"  Bucket: {bucket_name}")
    print(f"  Object: {object_key}")
    print(f"  Function: {function_name}")
    print()
    
    return invoke_lambda(function_name, s3_event, region)

def get_lambda_logs(function_name, region='us-east-2', limit=10):
    """Retrieve recent logs from a Lambda function"""
    logs_client = boto3.client('logs', region_name=region)
    lambda_client = boto3.client('lambda', region_name=region)
    
    try:
        # Get function configuration to find log group
        response = lambda_client.get_function(FunctionName=function_name)
        
        log_group_name = f"/aws/lambda/{function_name}"
        
        print(f"Retrieving logs from: {log_group_name}")
        
        # Get log streams
        streams_response = logs_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=5
        )
        
        if not streams_response['logStreams']:
            print("No log streams found")
            return
        
        # Get log events from most recent stream
        stream_name = streams_response['logStreams'][0]['logStreamName']
        
        events_response = logs_client.get_log_events(
            logGroupName=log_group_name,
            logStreamName=stream_name,
            limit=limit,
            startFromHead=False
        )
        
        print(f"\nRecent log events from {function_name}:")
        print("=" * 60)
        
        for event in events_response['events']:
            timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
            message = event['message'].strip()
            print(f"[{timestamp}] {message}")
        
        print("=" * 60)
        
    except logs_client.exceptions.ResourceNotFoundException:
        print(f"Log group not found: {log_group_name}")
        print("The Lambda function may not have been invoked yet")
    except Exception as e:
        print(f"✗ Error retrieving logs: {str(e)}")

def upload_test_file_to_s3(bucket_name, file_key='test/test-file.txt', region='us-east-2'):
    """Upload a test file to S3 to trigger Lambda"""
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        test_content = f"Test file uploaded at {datetime.utcnow().isoformat()}\n"
        test_content += "This is a test file to trigger the S3 upload logger Lambda function.\n"
        
        print(f"Uploading test file to s3://{bucket_name}/{file_key}...")
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_key,
            Body=test_content.encode('utf-8'),
            ContentType='text/plain'
        )
        
        print(f"✓ Test file uploaded successfully!")
        print(f"\nThis should trigger the Lambda function.")
        print("Wait a few seconds, then check CloudWatch Logs:")
        print(f"  Log Group: /aws/s3-uploads/git-captain")
        
        return True
        
    except Exception as e:
        print(f"✗ Error uploading test file: {str(e)}")
        return False

def check_cloudwatch_logs(log_group_name='/aws/s3-uploads/git-captain', region='us-east-2'):
    """Check CloudWatch Logs for S3 upload events"""
    logs_client = boto3.client('logs', region_name=region)
    
    try:
        # Get most recent log stream
        response = logs_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=1
        )
        
        if not response['logStreams']:
            print(f"No log streams found in {log_group_name}")
            return
        
        stream_name = response['logStreams'][0]['logStreamName']
        
        # Get recent log events
        events_response = logs_client.get_log_events(
            logGroupName=log_group_name,
            logStreamName=stream_name,
            limit=20,
            startFromHead=False
        )
        
        print(f"\nRecent S3 upload logs:")
        print("=" * 60)
        
        for event in events_response['events']:
            try:
                log_data = json.loads(event['message'])
                print(f"\nTimestamp: {log_data.get('timestamp')}")
                print(f"  Bucket:   {log_data.get('bucket')}")
                print(f"  Key:      {log_data.get('key')}")
                print(f"  Size:     {log_data.get('size_mb')} MB")
                print(f"  Type:     {log_data.get('content_type')}")
            except json.JSONDecodeError:
                # Not JSON, just print the message
                print(event['message'])
        
        print("=" * 60)
        
    except logs_client.exceptions.ResourceNotFoundException:
        print(f"Log group not found: {log_group_name}")
        print("No S3 uploads have been logged yet")
    except Exception as e:
        print(f"✗ Error checking logs: {str(e)}")

def main():
    """Main function for Lambda operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Git-Captain Lambda Testing')
    parser.add_argument('--region', default='us-east-2', help='AWS region')
    parser.add_argument('--test-s3-logger', action='store_true', help='Test S3 upload logger')
    parser.add_argument('--bucket', default='git-captain-logs-bucket', help='S3 bucket name')
    parser.add_argument('--key', default='test/test-upload.txt', help='S3 object key')
    parser.add_argument('--upload-test', action='store_true', help='Upload a test file to S3')
    parser.add_argument('--check-logs', action='store_true', help='Check CloudWatch logs')
    parser.add_argument('--lambda-logs', help='Get logs for specific Lambda function')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Git-Captain Lambda Testing")
    print("=" * 60)
    print()
    
    if args.test_s3_logger:
        test_s3_upload_logger(args.bucket, args.key, args.region)
    
    if args.upload_test:
        upload_test_file_to_s3(args.bucket, args.key, args.region)
    
    if args.check_logs:
        check_cloudwatch_logs(region=args.region)
    
    if args.lambda_logs:
        get_lambda_logs(args.lambda_logs, args.region)
    
    if not any([args.test_s3_logger, args.upload_test, args.check_logs, args.lambda_logs]):
        parser.print_help()
        print("\nExamples:")
        print("  # Test S3 logger with simulated event:")
        print("  python lambda_test.py --test-s3-logger")
        print()
        print("  # Upload a real test file to trigger Lambda:")
        print("  python lambda_test.py --upload-test --bucket git-captain-logs-bucket")
        print()
        print("  # Check CloudWatch logs for S3 uploads:")
        print("  python lambda_test.py --check-logs")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Unexpected error: {str(e)}")
        sys.exit(1)
