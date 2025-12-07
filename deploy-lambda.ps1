# Git-Captain AWS Lambda Deployment Script
# Deploys the application to AWS Lambda using SAM CLI

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment = "prod",
    
    [Parameter(Mandatory=$true)]
    [string]$GitHubClientId,
    
    [Parameter(Mandatory=$true)]
    [string]$GitHubClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$GitHubOrgName = "ConfusedDeer",
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-east-2",
    
    [Parameter(Mandatory=$false)]
    [string]$StackName = "git-captain-lambda"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Git-Captain Lambda Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

$commands = @("aws", "sam", "node", "npm")
foreach ($cmd in $commands) {
    try {
        $null = Get-Command $cmd -ErrorAction Stop
        Write-Host "  ✓ $cmd found" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ $cmd not found - please install it" -ForegroundColor Red
        exit 1
    }
}

# Install dependencies
Write-Host "`nInstalling Node.js dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ npm install failed" -ForegroundColor Red
    exit 1
}

# Build with SAM
Write-Host "`nBuilding Lambda function with SAM..." -ForegroundColor Yellow
sam build --template sam-lambda.yaml

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ SAM build failed" -ForegroundColor Red
    exit 1
}

# Deploy with SAM
Write-Host "`nDeploying to AWS Lambda..." -ForegroundColor Yellow
Write-Host "  Environment: $Environment" -ForegroundColor Gray
Write-Host "  Region: $Region" -ForegroundColor Gray
Write-Host "  Stack Name: $StackName" -ForegroundColor Gray
Write-Host ""

sam deploy `
    --template-file .aws-sam/build/template.yaml `
    --stack-name $StackName `
    --region $Region `
    --capabilities CAPABILITY_IAM `
    --parameter-overrides `
        "Environment=$Environment" `
        "GitHubClientId=$GitHubClientId" `
        "GitHubClientSecret=$GitHubClientSecret" `
        "GitHubOrgName=$GitHubOrgName" `
    --no-fail-on-empty-changeset `
    --resolve-s3

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n✗ Deployment failed" -ForegroundColor Red
    exit 1
}

# Get outputs
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Deployment Successful!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Fetching deployment outputs..." -ForegroundColor Yellow
$outputs = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query 'Stacks[0].Outputs' `
    --output json | ConvertFrom-Json

Write-Host "`nDeployment Information:" -ForegroundColor Cyan
foreach ($output in $outputs) {
    Write-Host "  $($output.OutputKey): $($output.OutputValue)" -ForegroundColor White
}

# Test the deployment
$apiUrl = ($outputs | Where-Object { $_.OutputKey -eq "ApiUrl" }).OutputValue
if ($apiUrl) {
    Write-Host "`nTesting health endpoint..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "${apiUrl}health" -Method Get
        Write-Host "✓ Health check passed!" -ForegroundColor Green
        Write-Host "  Status: $($response.status)" -ForegroundColor White
        Write-Host "  Runtime: $($response.runtime)" -ForegroundColor White
    } catch {
        Write-Host "⚠ Health check failed (may take a minute for API to be ready)" -ForegroundColor Yellow
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Update your GitHub OAuth App callback URL to:" -ForegroundColor White
Write-Host "   ${apiUrl}authenticated.html" -ForegroundColor Gray
Write-Host "2. Access your application at:" -ForegroundColor White
Write-Host "   $apiUrl" -ForegroundColor Gray
Write-Host "3. Monitor logs with:" -ForegroundColor White
Write-Host "   sam logs --stack-name $StackName --region $Region --tail" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
