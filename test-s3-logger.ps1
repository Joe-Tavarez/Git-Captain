# Test S3 Upload Logger Lambda
# Creates test files and uploads them to S3 to trigger the Lambda function

$ErrorActionPreference = "Stop"

Write-Host "`n=== Testing S3 Upload Logger ===" -ForegroundColor Cyan

$BucketName = "git-captain-logs-bucket"
$FunctionName = "git-captain-s3-logger"
$Region = "us-east-2"

# Create test files
Write-Host "`n[1/4] Creating test files..." -ForegroundColor Yellow
$TestFile1 = "test-upload-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$TestFile2 = "test-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

"This is a test file uploaded at $(Get-Date)" | Out-File $TestFile1
"[INFO] Test log entry - S3 Logger Lambda Test" | Out-File $TestFile2

Write-Host "✓ Created: $TestFile1" -ForegroundColor Green
Write-Host "✓ Created: $TestFile2" -ForegroundColor Green

# Upload files to S3
Write-Host "`n[2/4] Uploading files to S3..." -ForegroundColor Yellow

aws s3 cp $TestFile1 s3://$BucketName/ --region $Region
Write-Host "✓ Uploaded: $TestFile1" -ForegroundColor Green

Start-Sleep -Seconds 2

aws s3 cp $TestFile2 s3://$BucketName/ --region $Region
Write-Host "✓ Uploaded: $TestFile2" -ForegroundColor Green

# Wait for Lambda to process
Write-Host "`n[3/4] Waiting for Lambda to process (5 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# View CloudWatch logs
Write-Host "`n[4/4] Fetching CloudWatch logs..." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Gray

aws logs tail /aws/lambda/$FunctionName --since 2m --region $Region

Write-Host "----------------------------------------" -ForegroundColor Gray

# Cleanup local files
Remove-Item $TestFile1 -ErrorAction SilentlyContinue
Remove-Item $TestFile2 -ErrorAction SilentlyContinue

Write-Host "`n=== Test Complete ===" -ForegroundColor Green
Write-Host "`nTo view live logs, run:" -ForegroundColor Yellow
Write-Host "  aws logs tail /aws/lambda/$FunctionName --follow --region $Region" -ForegroundColor White
Write-Host "`nTo list files in bucket:" -ForegroundColor Yellow
Write-Host "  aws s3 ls s3://$BucketName/ --region $Region" -ForegroundColor White
Write-Host ""
