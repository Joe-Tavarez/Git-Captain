# Complete the deployment
Write-Host "Monitoring deployments..." -ForegroundColor Cyan

# Wait for RDS
Write-Host "`n[1/3] Waiting for RDS (5-10 min)..." -ForegroundColor Yellow
aws cloudformation wait stack-create-complete --stack-name git-captain-rds --region us-east-2
if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: RDS complete!" -ForegroundColor Green
} else {
    Write-Host "ERROR: RDS failed!" -ForegroundColor Red
    exit 1
}

# Deploy Lambda
Write-Host "`n[2/3] Deploying Lambda..." -ForegroundColor Yellow
cd c:\Users\jtava\OneDrive\Documents\GitHub\Git-Captain\cloudformation
aws cloudformation create-stack --stack-name git-captain-lambda --template-body file://lambda-s3-logging.yaml --capabilities CAPABILITY_IAM --region us-east-2
aws cloudformation wait stack-create-complete --stack-name git-captain-lambda --region us-east-2
if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: Lambda complete!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Lambda failed!" -ForegroundColor Red
    exit 1
}

# Deploy EC2/ALB
Write-Host "`n[3/3] Deploying EC2/ALB (10-15 min)..." -ForegroundColor Yellow
aws cloudformation create-stack --stack-name git-captain-ec2-alb --template-body file://ec2-alb-autoscaling.yaml --capabilities CAPABILITY_IAM --region us-east-2
aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-alb --region us-east-2
if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: EC2/ALB complete!" -ForegroundColor Green
} else {
    Write-Host "ERROR: EC2/ALB failed!" -ForegroundColor Red
    exit 1
}

# Get URL
$albDns = aws elbv2 describe-load-balancers --names git-captain-prod-alb --query 'LoadBalancers[0].DNSName' --output text --region us-east-2

Write-Host "`n===============================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Application URL: http://$albDns" -ForegroundColor Cyan
Write-Host "Health Check: http://$albDns/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test it: curl http://$albDns/health" -ForegroundColor Yellow
