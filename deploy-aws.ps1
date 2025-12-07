# Git-Captain AWS Deployment Script
# This script automates the complete AWS infrastructure deployment

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Git-Captain AWS Infrastructure Deployment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"
$ProjectRoot = "c:\Users\jtava\OneDrive\Documents\GitHub\Git-Captain"

# Step 1: Deploy Terraform Infrastructure
Write-Host "[Step 1/6] Deploying Terraform Infrastructure (VPC, Security Groups, NAT)..." -ForegroundColor Yellow
Write-Host "This will take approximately 3-5 minutes..." -ForegroundColor Gray
Write-Host ""

Set-Location "$ProjectRoot\terraform"

Write-Host "Running: terraform init" -ForegroundColor Gray
terraform init

Write-Host "`nRunning: terraform validate" -ForegroundColor Gray
terraform validate

Write-Host "`nRunning: terraform apply" -ForegroundColor Gray
terraform apply -auto-approve

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Terraform deployment failed!" -ForegroundColor Red
    Write-Host "Please check the error messages above and try again." -ForegroundColor Red
    exit 1
}

Write-Host "`n[SUCCESS] Terraform infrastructure deployed!" -ForegroundColor Green
Write-Host ""

# Verify Terraform outputs
Write-Host "Verifying Terraform outputs..." -ForegroundColor Gray
$vpcId = terraform output -raw vpc_id
Write-Host "VPC ID: $vpcId" -ForegroundColor Green

# Step 2: Verify SSM Parameters
Write-Host "`n[Step 2/6] Verifying SSM Parameters..." -ForegroundColor Yellow
Write-Host ""

$ssmParams = @(
    "/git-captain/infrastructure/vpc-id",
    "/git-captain/infrastructure/public-subnet-ids",
    "/git-captain/infrastructure/private-subnet-ids",
    "/git-captain/infrastructure/alb-security-group-id",
    "/git-captain/infrastructure/ec2-security-group-id",
    "/git-captain/infrastructure/rds-security-group-id"
)

foreach ($param in $ssmParams) {
    try {
        $value = aws ssm get-parameter --name $param --query 'Parameter.Value' --output text 2>$null
        if ($value) {
            Write-Host "  ✓ $param" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $param (not found)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ✗ $param (error)" -ForegroundColor Red
    }
}

Write-Host ""

# Step 3: Deploy CloudFormation Stacks
Write-Host "[Step 3/6] Deploying CloudFormation Stacks..." -ForegroundColor Yellow
Write-Host "This will take approximately 15-20 minutes..." -ForegroundColor Gray
Write-Host ""

Set-Location "$ProjectRoot\cloudformation"

# Deploy RDS
Write-Host "Deploying RDS Database Stack..." -ForegroundColor Cyan
aws cloudformation create-stack `
    --stack-name git-captain-rds `
    --template-body file://rds.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ RDS stack creation initiated" -ForegroundColor Green
} else {
    Write-Host "  ✗ RDS stack creation failed" -ForegroundColor Red
}

# Deploy Lambda
Write-Host "`nDeploying Lambda S3 Logger Stack..." -ForegroundColor Cyan
aws cloudformation create-stack `
    --stack-name git-captain-lambda `
    --template-body file://lambda-s3-logging.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Lambda stack creation initiated" -ForegroundColor Green
} else {
    Write-Host "  ✗ Lambda stack creation failed" -ForegroundColor Red
}

# Deploy EC2/ALB/Auto Scaling
Write-Host "`nDeploying EC2/ALB/Auto Scaling Stack..." -ForegroundColor Cyan
Write-Host "  (This stack takes 10-15 minutes to complete)" -ForegroundColor Gray
aws cloudformation create-stack `
    --stack-name git-captain-ec2-alb `
    --template-body file://ec2-alb-autoscaling.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ EC2/ALB stack creation initiated" -ForegroundColor Green
} else {
    Write-Host "  ✗ EC2/ALB stack creation failed" -ForegroundColor Red
}

# Deploy CloudWatch Monitoring
Write-Host "`nDeploying CloudWatch Monitoring Stack..." -ForegroundColor Cyan
aws cloudformation create-stack `
    --stack-name git-captain-monitoring `
    --template-body file://cloudwatch-monitoring.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Monitoring stack creation initiated" -ForegroundColor Green
} else {
    Write-Host "  ✗ Monitoring stack creation failed" -ForegroundColor Red
}

# Deploy WAF
Write-Host "`nDeploying AWS WAF Stack..." -ForegroundColor Cyan
aws cloudformation create-stack `
    --stack-name git-captain-waf `
    --template-body file://waf.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ WAF stack creation initiated" -ForegroundColor Green
} else {
    Write-Host "  ✗ WAF stack creation failed" -ForegroundColor Red
}

Write-Host ""

# Step 4: Wait for Critical Stacks
Write-Host "[Step 4/6] Waiting for critical stacks to complete..." -ForegroundColor Yellow
Write-Host "This may take 10-15 minutes. You can press Ctrl+C to stop waiting and check manually." -ForegroundColor Gray
Write-Host ""

Write-Host "Waiting for RDS stack..." -ForegroundColor Cyan
aws cloudformation wait stack-create-complete --stack-name git-captain-rds --region us-east-2
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ RDS stack complete" -ForegroundColor Green
}

Write-Host "`nWaiting for EC2/ALB stack..." -ForegroundColor Cyan
aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-alb --region us-east-2
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ EC2/ALB stack complete" -ForegroundColor Green
}

# Step 5: Get Application URL
Write-Host "`n[Step 5/6] Retrieving Application URL..." -ForegroundColor Yellow
Write-Host ""

try {
    $albDns = aws elbv2 describe-load-balancers `
        --names git-captain-prod-alb `
        --query 'LoadBalancers[0].DNSName' `
        --output text `
        --region us-east-2 2>$null
    
    if ($albDns) {
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "  Application URL: http://$albDns" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Health Endpoint: http://$albDns/health" -ForegroundColor Cyan
        Write-Host "Main Application: http://$albDns" -ForegroundColor Cyan
    } else {
        Write-Host "  [INFO] ALB not ready yet. Wait a few minutes and check AWS Console." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [INFO] Could not retrieve ALB DNS. Check AWS Console." -ForegroundColor Yellow
}

Write-Host ""

# Step 6: Summary
Write-Host "[Step 6/6] Deployment Summary" -ForegroundColor Yellow
Write-Host ""

Write-Host "Checking stack statuses..." -ForegroundColor Gray
Write-Host ""

$stacks = @(
    "git-captain-rds",
    "git-captain-lambda",
    "git-captain-ec2-alb",
    "git-captain-monitoring",
    "git-captain-waf"
)

foreach ($stack in $stacks) {
    try {
        $status = aws cloudformation describe-stacks `
            --stack-name $stack `
            --query 'Stacks[0].StackStatus' `
            --output text `
            --region us-east-2 2>$null
        
        if ($status -match "COMPLETE") {
            Write-Host "  ✓ $stack : $status" -ForegroundColor Green
        } elseif ($status -match "IN_PROGRESS") {
            Write-Host "  ⏳ $stack : $status" -ForegroundColor Yellow
        } else {
            Write-Host "  ✗ $stack : $status" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ? $stack : Unknown" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Deployment Script Complete!" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Wait for all stacks to reach CREATE_COMPLETE status" -ForegroundColor White
Write-Host "2. Configure GitHub OAuth with the ALB DNS name" -ForegroundColor White
Write-Host "3. Test the application at: http://<ALB-DNS>" -ForegroundColor White
Write-Host ""
Write-Host "To check stack status:" -ForegroundColor Yellow
Write-Host "  aws cloudformation describe-stacks --stack-name git-captain-ec2-alb" -ForegroundColor Gray
Write-Host ""
Write-Host "To view application logs:" -ForegroundColor Yellow
Write-Host "  aws logs tail /aws/ec2/git-captain --follow" -ForegroundColor Gray
Write-Host ""
Write-Host "For detailed documentation, see:" -ForegroundColor Yellow
Write-Host "  - docs\aws\DEPLOYMENT_GUIDE.md" -ForegroundColor Gray
Write-Host "  - AWS_DEPLOYMENT_CHECKLIST.md" -ForegroundColor Gray
Write-Host ""

Set-Location $ProjectRoot
