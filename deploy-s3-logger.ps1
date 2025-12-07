# Deploy S3 Upload Logger Lambda Function
# This script deploys a Python Lambda that logs S3 uploads to CloudWatch

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=== Deploying S3 Upload Logger Lambda ===" -ForegroundColor Cyan
Write-Host ""

# Configuration
$FunctionName = "git-captain-s3-logger"
$BucketName = "git-captain-logs-bucket"
$Region = "us-east-2"
$RoleName = "git-captain-s3-logger-role"

# Step 1: Create IAM Role for Lambda
Write-Host "[1/6] Creating IAM role..." -ForegroundColor Yellow

$TrustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"@

aws iam create-role --role-name $RoleName --assume-role-policy-document $TrustPolicy --region $Region 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Created IAM role: $RoleName" -ForegroundColor Green
} else {
    Write-Host "IAM role already exists" -ForegroundColor Yellow
}

# Step 2: Attach policies
Write-Host ""
Write-Host "[2/6] Attaching IAM policies..." -ForegroundColor Yellow

aws iam attach-role-policy --role-name $RoleName --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole --region $Region 2>$null
aws iam attach-role-policy --role-name $RoleName --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess --region $Region 2>$null

Write-Host "Policies attached" -ForegroundColor Green

# Wait for role to propagate
Write-Host ""
Write-Host "[3/6] Waiting for IAM role to propagate (10 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Step 3: Package Lambda function
Write-Host ""
Write-Host "[4/6] Packaging Lambda function..." -ForegroundColor Yellow

$ZipFile = "s3-logger-deployment.zip"
if (Test-Path $ZipFile) { Remove-Item $ZipFile }

Compress-Archive -Path lambda\s3-upload-logger.py -DestinationPath $ZipFile -CompressionLevel Fastest

Write-Host "Lambda package created: $ZipFile" -ForegroundColor Green

# Step 4: Create or update Lambda function
Write-Host ""
Write-Host "[5/6] Deploying Lambda function..." -ForegroundColor Yellow

$AccountId = (aws sts get-caller-identity --query Account --output text)
$RoleArn = "arn:aws:iam::${AccountId}:role/${RoleName}"

# Try to create the function
aws lambda create-function --function-name $FunctionName --runtime python3.9 --role $RoleArn --handler s3-upload-logger.lambda_handler --zip-file fileb://$ZipFile --timeout 30 --memory-size 128 --region $Region 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Lambda function created: $FunctionName" -ForegroundColor Green
} else {
    Write-Host "Function exists, updating code..." -ForegroundColor Yellow
    aws lambda update-function-code --function-name $FunctionName --zip-file fileb://$ZipFile --region $Region
    Write-Host "Lambda function updated: $FunctionName" -ForegroundColor Green
}

# Step 5: Configure S3 event trigger
Write-Host ""
Write-Host "[6/6] Configuring S3 event trigger..." -ForegroundColor Yellow

# Add Lambda permission to be invoked by S3
$StatementId = "S3InvokePermission"
aws lambda add-permission --function-name $FunctionName --statement-id $StatementId --action lambda:InvokeFunction --principal s3.amazonaws.com --source-arn arn:aws:s3:::$BucketName --region $Region 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Lambda permission added" -ForegroundColor Green
} else {
    Write-Host "Permission already exists" -ForegroundColor Yellow
}

# Create S3 notification configuration
$LambdaArn = "arn:aws:lambda:${Region}:${AccountId}:function:${FunctionName}"

$NotificationConfig = @"
{
  "LambdaFunctionConfigurations": [
    {
      "Id": "S3UploadLogger",
      "LambdaFunctionArn": "$LambdaArn",
      "Events": ["s3:ObjectCreated:*"]
    }
  ]
}
"@

# Save to temp file
$ConfigFile = "s3-notification-config.json"
$NotificationConfig | Out-File -FilePath $ConfigFile -Encoding utf8

# Apply notification configuration
aws s3api put-bucket-notification-configuration --bucket $BucketName --notification-configuration file://$ConfigFile --region $Region

Write-Host "S3 event trigger configured" -ForegroundColor Green

# Cleanup
Remove-Item $ConfigFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Deployment Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Function Name: $FunctionName" -ForegroundColor Cyan
Write-Host "S3 Bucket: $BucketName" -ForegroundColor Cyan
Write-Host "Region: $Region" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test by uploading a file to S3:" -ForegroundColor Yellow
Write-Host "aws s3 cp test.txt s3://$BucketName/" -ForegroundColor White
Write-Host ""
Write-Host "View logs in CloudWatch:" -ForegroundColor Yellow
Write-Host "aws logs tail /aws/lambda/$FunctionName --follow --region $Region" -ForegroundColor White
Write-Host ""
