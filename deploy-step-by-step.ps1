# Step-by-Step AWS Deployment for Git-Captain
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Git-Captain AWS Step-by-Step Deployment" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

$ProjectRoot = "c:\Users\jtava\OneDrive\Documents\GitHub\Git-Captain"

# Step 1: RDS (no dependencies)
Write-Host "`n[1/3] Deploying RDS Database..." -ForegroundColor Yellow
Set-Location "$ProjectRoot\cloudformation"

aws cloudformation create-stack `
    --stack-name git-captain-rds `
    --template-body file://rds.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

Write-Host "Waiting for RDS stack (5-10 min)..." -ForegroundColor Gray
aws cloudformation wait stack-create-complete --stack-name git-captain-rds --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: RDS deployed!" -ForegroundColor Green
} else {
    Write-Host "ERROR: RDS deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 2: Lambda (no dependencies)
Write-Host "`n[2/3] Deploying Lambda S3 Logger..." -ForegroundColor Yellow

aws cloudformation create-stack `
    --stack-name git-captain-lambda `
    --template-body file://lambda-s3-logging.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

Write-Host "Waiting for Lambda stack (2-3 min)..." -ForegroundColor Gray
aws cloudformation wait stack-create-complete --stack-name git-captain-lambda --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: Lambda deployed!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Lambda deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 3: EC2/ALB (no dependencies)
Write-Host "`n[3/3] Deploying EC2/ALB/Auto Scaling..." -ForegroundColor Yellow

aws cloudformation create-stack `
    --stack-name git-captain-ec2-alb `
    --template-body file://ec2-alb-autoscaling.yaml `
    --capabilities CAPABILITY_IAM `
    --region us-east-2

Write-Host "Waiting for EC2/ALB stack (10-15 min)..." -ForegroundColor Gray
aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-alb --region us-east-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: EC2/ALB deployed!" -ForegroundColor Green
} else {
    Write-Host "ERROR: EC2/ALB deployment failed!" -ForegroundColor Red
    Write-Host "Check AWS Console for details" -ForegroundColor Yellow
    exit 1
}

# Get outputs
Write-Host "`nRetrieving stack outputs..." -ForegroundColor Yellow

$albDns = aws elbv2 describe-load-balancers `
    --names git-captain-prod-alb `
    --query 'LoadBalancers[0].DNSName' `
    --output text `
    --region us-east-2

$albArn = aws elbv2 describe-load-balancers `
    --names git-captain-prod-alb `
    --query 'LoadBalancers[0].LoadBalancerArn' `
    --output text `
    --region us-east-2

if ($albDns) {
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host " APPLICATION DEPLOYED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Application URL:" -ForegroundColor Cyan
    Write-Host "  http://$albDns" -ForegroundColor White
    Write-Host ""
    Write-Host "Health Check:" -ForegroundColor Cyan
    Write-Host "  http://$albDns/health" -ForegroundColor White
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Test health endpoint: curl http://$albDns/health" -ForegroundColor White
    Write-Host "2. Configure GitHub OAuth with this URL" -ForegroundColor White
    Write-Host "3. Access application: http://$albDns" -ForegroundColor White
    Write-Host ""
    Write-Host "Optional: Deploy monitoring and WAF" -ForegroundColor Yellow
    Write-Host "  See deploy-monitoring.ps1" -ForegroundColor Gray
}

Set-Location $ProjectRoot
