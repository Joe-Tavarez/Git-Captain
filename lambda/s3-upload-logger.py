"""
S3 Upload Logger Lambda Function
Logs new file uploads to git-captain-logs-bucket into CloudWatch Logs

This Lambda function is triggered by S3 events and logs details about uploaded files.
Required for academic project: AWS Lambda logging S3 uploads to CloudWatch.
"""

import json
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Lambda handler triggered by S3 events.
    Logs file upload details to CloudWatch Logs.
    
    Args:
        event: S3 event notification
        context: Lambda context object
        
    Returns:
        dict: Response with status code and message
    """
    
    logger.info("S3 Upload Logger Lambda triggered")
    logger.info(f"Event received: {json.dumps(event, indent=2)}")
    
    try:
        # Process each S3 record in the event
        for record in event['Records']:
            # Extract S3 event details
            event_name = record['eventName']
            event_time = record['eventTime']
            
            # Extract S3 bucket and object information
            s3_info = record['s3']
            bucket_name = s3_info['bucket']['name']
            object_key = s3_info['object']['key']
            object_size = s3_info['object'].get('size', 0)
            
            # Extract requester information if available
            requester = record.get('userIdentity', {}).get('principalId', 'Unknown')
            
            # Log structured information
            log_message = {
                'timestamp': event_time,
                'event': event_name,
                'bucket': bucket_name,
                'file': object_key,
                'size_bytes': object_size,
                'size_kb': round(object_size / 1024, 2),
                'requester': requester
            }
            
            logger.info(f"File Upload Details: {json.dumps(log_message, indent=2)}")
            logger.info(f"✓ New file uploaded to S3: {bucket_name}/{object_key} ({object_size} bytes)")
            
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully logged {len(event["Records"])} S3 upload event(s)',
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except KeyError as e:
        error_msg = f"Missing expected key in S3 event: {str(e)}"
        logger.error(error_msg)
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': error_msg,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        error_msg = f"Error processing S3 event: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_msg,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
