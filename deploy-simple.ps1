# Simple AWS Deployment Script for Git-Captain
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Git-Captain AWS Deployment" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

$ProjectRoot = "c:\Users\jtava\OneDrive\Documents\GitHub\Git-Captain"

# Step 1: Terraform
Write-Host "`n[1/3] Deploying Terraform..." -ForegroundColor Yellow
Set-Location "$ProjectRoot\terraform"
terraform init
terraform apply -auto-approve

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Terraform failed!" -ForegroundColor Red
    exit 1
}

Write-Host "SUCCESS: Terraform deployed!" -ForegroundColor Green
$vpcId = terraform output -raw vpc_id
Write-Host "VPC ID: $vpcId" -ForegroundColor Cyan

# Step 2: CloudFormation
Write-Host "`n[2/3] Deploying CloudFormation..." -ForegroundColor Yellow
Set-Location "$ProjectRoot\cloudformation"

Write-Host "Creating RDS stack..." -ForegroundColor Cyan
aws cloudformation create-stack --stack-name git-captain-rds --template-body file://rds.yaml --capabilities CAPABILITY_IAM --region us-east-2

Write-Host "Creating Lambda stack..." -ForegroundColor Cyan
aws cloudformation create-stack --stack-name git-captain-lambda --template-body file://lambda-s3-logging.yaml --capabilities CAPABILITY_IAM --region us-east-2

Write-Host "Creating EC2/ALB stack..." -ForegroundColor Cyan
aws cloudformation create-stack --stack-name git-captain-ec2-alb --template-body file://ec2-alb-autoscaling.yaml --capabilities CAPABILITY_IAM --region us-east-2

Write-Host "Creating Monitoring stack..." -ForegroundColor Cyan
aws cloudformation create-stack --stack-name git-captain-monitoring --template-body file://cloudwatch-monitoring.yaml --capabilities CAPABILITY_IAM --region us-east-2

Write-Host "Creating WAF stack..." -ForegroundColor Cyan
aws cloudformation create-stack --stack-name git-captain-waf --template-body file://waf.yaml --capabilities CAPABILITY_IAM --region us-east-2

# Step 3: Wait
Write-Host "`n[3/3] Waiting for EC2/ALB stack (10-15 min)..." -ForegroundColor Yellow
Write-Host "You can press Ctrl+C to stop waiting" -ForegroundColor Gray
aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-alb --region us-east-2

# Get URL
Write-Host "`nGetting Application URL..." -ForegroundColor Yellow
$albDns = aws elbv2 describe-load-balancers --names git-captain-prod-alb --query 'LoadBalancers[0].DNSName' --output text --region us-east-2

if ($albDns) {
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host " APPLICATION URL" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host " http://$albDns" -ForegroundColor Cyan
    Write-Host " http://$albDns/health" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Green
}

Write-Host "`nDeployment complete!" -ForegroundColor Green
Set-Location $ProjectRoot
