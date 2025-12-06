# Deploy Git-Captain Serverless Stack
# Run this script from the project root directory

param(
    [Parameter(Mandatory=$false)]
    [string]$GitHubClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$GitHubClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$GitHubOrgName = "ConfusedDeer",
    
    [Parameter(Mandatory=$false)]
    [string]$AwsRegion = "us-east-2",
    
    [Parameter(Mandatory=$false)]
    [string]$StackName = "git-captain-serverless",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipConfirmation
)

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Git-Captain Serverless Deployment" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check if AWS CLI is installed
try {
    $null = aws --version
} catch {
    Write-Host "ERROR: AWS CLI not found. Please install it first." -ForegroundColor Red
    Write-Host "Download from: https://aws.amazon.com/cli/" -ForegroundColor Yellow
    exit 1
}

# Check if SAM CLI is installed
try {
    $null = sam --version
} catch {
    Write-Host "ERROR: AWS SAM CLI not found. Please install it first." -ForegroundColor Red
    Write-Host "Run: pip install aws-sam-cli" -ForegroundColor Yellow
    exit 1
}

# Check if credentials are provided
if (-not $GitHubClientId) {
    $GitHubClientId = Read-Host "Enter GitHub OAuth Client ID"
}

if (-not $GitHubClientSecret) {
    $GitHubClientSecret = Read-Host "Enter GitHub OAuth Client Secret" -AsSecureString
    $GitHubClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($GitHubClientSecret))
}

Write-Host ""
Write-Host "Deployment Configuration:" -ForegroundColor Green
Write-Host "  Stack Name: $StackName" -ForegroundColor White
Write-Host "  AWS Region: $AwsRegion" -ForegroundColor White
Write-Host "  GitHub Org: $GitHubOrgName" -ForegroundColor White
Write-Host "  GitHub Client ID: $GitHubClientId" -ForegroundColor White
Write-Host ""

if (-not $SkipConfirmation) {
    $confirm = Read-Host "Continue with deployment? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Step 1: Install Lambda dependencies
Write-Host ""
Write-Host "Step 1: Installing Lambda dependencies..." -ForegroundColor Cyan
Push-Location lambda
try {
    npm install --production
    if ($LASTEXITCODE -ne 0) {
        throw "npm install failed"
    }
} catch {
    Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "✓ Dependencies installed" -ForegroundColor Green

# Step 2: Build SAM application
Write-Host ""
Write-Host "Step 2: Building SAM application..." -ForegroundColor Cyan
sam build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: SAM build failed" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Build completed" -ForegroundColor Green

# Step 3: Deploy SAM application
Write-Host ""
Write-Host "Step 3: Deploying to AWS..." -ForegroundColor Cyan
sam deploy `
    --no-confirm-changeset `
    --no-fail-on-empty-changeset `
    --stack-name $StackName `
    --capabilities CAPABILITY_IAM `
    --region $AwsRegion `
    --parameter-overrides `
        GitHubClientId=$GitHubClientId `
        GitHubClientSecret=$GitHubClientSecret `
        GitHubOrgName=$GitHubOrgName

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: SAM deployment failed" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Deployment completed" -ForegroundColor Green

# Step 4: Get S3 bucket name
Write-Host ""
Write-Host "Step 4: Retrieving S3 bucket name..." -ForegroundColor Cyan
$bucketName = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $AwsRegion `
    --query "Stacks[0].Outputs[?OutputKey=='StaticAssetsBucket'].OutputValue" `
    --output text

if (-not $bucketName) {
    Write-Host "ERROR: Could not retrieve S3 bucket name" -ForegroundColor Red
    exit 1
}
Write-Host "✓ S3 Bucket: $bucketName" -ForegroundColor Green

# Step 5: Sync static assets to S3
Write-Host ""
Write-Host "Step 5: Uploading static assets to S3..." -ForegroundColor Cyan
aws s3 sync public/ "s3://$bucketName/" `
    --delete `
    --exclude "*.md" `
    --exclude ".DS_Store" `
    --region $AwsRegion

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to sync static assets" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Static assets uploaded" -ForegroundColor Green

# Step 6: Get deployment outputs
Write-Host ""
Write-Host "Step 6: Retrieving deployment information..." -ForegroundColor Cyan
$apiUrl = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $AwsRegion `
    --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" `
    --output text

$cloudFrontUrl = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $AwsRegion `
    --query "Stacks[0].Outputs[?OutputKey=='CloudFrontUrl'].OutputValue" `
    --output text

# Display results
Write-Host ""
Write-Host "==================================" -ForegroundColor Green
Write-Host "  Deployment Successful! 🚀" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green
Write-Host ""
Write-Host "Application URLs:" -ForegroundColor Cyan
Write-Host "  API Gateway:  $apiUrl" -ForegroundColor White
Write-Host "  CloudFront:   https://$cloudFrontUrl" -ForegroundColor White
Write-Host "  S3 Bucket:    $bucketName" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Update GitHub OAuth App callback URL to:" -ForegroundColor White
Write-Host "     https://$cloudFrontUrl/views/authenticated.html" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Access your application at:" -ForegroundColor White
Write-Host "     https://$cloudFrontUrl" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Monitor logs with:" -ForegroundColor White
Write-Host "     aws logs tail /aws/lambda/git-captain-branch-operations --follow" -ForegroundColor Gray
Write-Host ""
Write-Host "==================================" -ForegroundColor Green
