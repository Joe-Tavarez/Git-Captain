# Git-Captain Serverless Deployment Guide

This guide will help you deploy Git-Captain as a fully serverless application on AWS.

## Architecture Overview

```
┌─────────────┐
│   GitHub    │
│   OAuth     │
└──────┬──────┘
       │
┌──────▼──────────────────────────────────────────────┐
│              CloudFront (CDN)                        │
│  - Static Assets (HTML, CSS, JS)                     │
│  - API Proxy to API Gateway                          │
└──────┬──────────────────────────────────────────────┘
       │
       ├─────────────────┐
       │                 │
┌──────▼──────┐   ┌─────▼──────────────────────────┐
│   S3 Bucket │   │      API Gateway                │
│   (Static)  │   │  - REST API                     │
└─────────────┘   └─────┬──────────────────────────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
        ┌─────▼───┐ ┌──▼────┐ ┌─▼──────┐
        │ Lambda  │ │Lambda │ │Lambda  │
        │ Health  │ │OAuth  │ │Branches│
        └─────────┘ └───┬───┘ └───┬────┘
                        │         │
                  ┌─────▼─────────▼────┐
                  │  Secrets Manager    │
                  │  (GitHub Creds)     │
                  └─────────────────────┘
```

## Prerequisites

### 1. AWS Account Setup
- AWS Account with appropriate permissions
- AWS CLI installed and configured
- AWS SAM CLI installed

### 2. Install AWS SAM CLI
```bash
# macOS
brew install aws-sam-cli

# Windows
choco install aws-sam-cli

# Linux
pip install aws-sam-cli
```

### 3. GitHub OAuth App
Create a new OAuth App at https://github.com/settings/developers:
- **Application name**: Git-Captain (or your choice)
- **Homepage URL**: `https://your-cloudfront-url` (you'll update this after deployment)
- **Authorization callback URL**: `https://your-cloudfront-url/views/authenticated.html`
- Save the **Client ID** and **Client Secret**

## Deployment Steps

### Step 1: Install Dependencies

```bash
# Navigate to project root
cd Git-Captain

# Install Lambda function dependencies
cd lambda
npm install
cd ..
```

### Step 2: Build the SAM Application

```bash
sam build
```

This creates a `.aws-sam` directory with your built application.

### Step 3: Deploy with SAM (Guided - First Time)

```bash
sam deploy --guided
```

You'll be prompted for:
- **Stack Name**: `git-captain-serverless` (or your choice)
- **AWS Region**: `us-east-2` (or your preferred region)
- **Parameter GitHubClientId**: Your GitHub OAuth Client ID
- **Parameter GitHubClientSecret**: Your GitHub OAuth Client Secret  
- **Parameter GitHubOrgName**: Your GitHub username or organization name
- **Parameter DomainName**: (Optional) Leave blank or enter custom domain
- **Confirm changes before deploy**: Y
- **Allow SAM CLI IAM role creation**: Y
- **Disable rollback**: N
- **Save arguments to configuration file**: Y
- **SAM configuration file**: `samconfig.toml`
- **SAM configuration environment**: `default`

### Step 4: Upload Static Assets to S3

After deployment completes, get the S3 bucket name:

```bash
# Get bucket name from stack outputs
aws cloudformation describe-stacks \
  --stack-name git-captain-serverless \
  --query "Stacks[0].Outputs[?OutputKey=='StaticAssetsBucket'].OutputValue" \
  --output text
```

Upload your static files:

```bash
# Replace YOUR-BUCKET-NAME with the actual bucket name
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ \
  --delete \
  --exclude "*.md" \
  --exclude ".DS_Store"
```

### Step 5: Get Deployment Outputs

```bash
# Get all stack outputs
aws cloudformation describe-stacks \
  --stack-name git-captain-serverless \
  --query "Stacks[0].Outputs" \
  --output table
```

You'll see:
- **ApiUrl**: Your API Gateway endpoint
- **CloudFrontUrl**: Your CloudFront distribution URL (this is your app URL)
- **StaticAssetsBucket**: S3 bucket name
- **SecretsArn**: Secrets Manager ARN

### Step 6: Update GitHub OAuth App

1. Go to your GitHub OAuth App settings
2. Update **Homepage URL** to: `https://YOUR-CLOUDFRONT-URL`
3. Update **Authorization callback URL** to: `https://YOUR-CLOUDFRONT-URL/views/authenticated.html`
4. Save changes

### Step 7: Test Your Application

Visit your CloudFront URL: `https://YOUR-CLOUDFRONT-URL`

## Subsequent Deployments

After the initial setup, deploying updates is simple:

```bash
# Build and deploy
sam build && sam deploy

# Sync static assets if changed
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete
```

## GitHub Actions Automation

To enable automatic deployments on push:

### 1. Create GitHub Secrets

Go to your repository → Settings → Secrets and variables → Actions

Add these secrets:
- `AWS_ACCESS_KEY_ID`: Your AWS access key
- `AWS_SECRET_ACCESS_KEY`: Your AWS secret key
- `AWS_REGION`: Your AWS region (e.g., `us-east-2`)
- `GITHUB_CLIENT_ID`: Your GitHub OAuth Client ID
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth Client Secret
- `GITHUB_ORG_NAME`: Your GitHub username/organization

### 2. Enable Workflow

The workflow file `.github/workflows/deploy-serverless.yml` is already configured.
Push to `main` or `feature/AWS` branch to trigger deployment.

## Monitoring and Logs

### CloudWatch Logs

View logs for each Lambda function:

```bash
# Health check logs
aws logs tail /aws/lambda/git-captain-health-check --follow

# OAuth logs
aws logs tail /aws/lambda/git-captain-github-oauth --follow

# Branch operations logs
aws logs tail /aws/lambda/git-captain-branch-operations --follow

# Status logs
aws logs tail /aws/lambda/git-captain-github-status --follow
```

### CloudWatch Metrics

Monitor in AWS Console:
1. Go to CloudWatch → Metrics → Lambda
2. View invocations, errors, duration, throttles

## Cost Estimate

For moderate usage (~1000-5000 requests/month):
- **Lambda**: Free tier (1M requests/month free)
- **API Gateway**: $3.50 per million requests (~$0.02/month)
- **S3**: $0.023 per GB (~$0.10/month for static assets)
- **CloudFront**: $0.085 per GB (~$0.50/month)
- **Secrets Manager**: $0.40/month per secret

**Total estimated cost: < $2/month** for moderate use

## Troubleshooting

### Issue: OAuth fails after deployment

**Solution**: 
1. Verify GitHub OAuth App callback URL matches CloudFront URL
2. Check Secrets Manager has correct credentials:
   ```bash
   aws secretsmanager get-secret-value --secret-id git-captain/github-oauth
   ```

### Issue: Static assets not loading

**Solution**:
1. Verify S3 sync completed successfully
2. Check S3 bucket policy allows public read
3. Check CloudFront distribution is deployed (can take 15-20 minutes)
4. Clear CloudFront cache:
   ```bash
   aws cloudfront create-invalidation --distribution-id YOUR-DIST-ID --paths "/*"
   ```

### Issue: API errors (500)

**Solution**:
1. Check Lambda function logs in CloudWatch
2. Verify environment variables are set correctly
3. Test Lambda function directly:
   ```bash
   sam local invoke HealthCheckFunction
   ```

### Issue: Permission errors

**Solution**:
1. Verify IAM roles have correct permissions
2. Check Lambda execution role can access Secrets Manager
3. Redeploy with `--capabilities CAPABILITY_IAM`

## Cleanup

To delete all resources and avoid charges:

```bash
# Empty S3 bucket first
aws s3 rm s3://YOUR-BUCKET-NAME --recursive

# Delete CloudFormation stack
sam delete --stack-name git-captain-serverless

# Verify deletion
aws cloudformation describe-stacks --stack-name git-captain-serverless
```

## Advanced Configuration

### Custom Domain

1. Request ACM certificate in `us-east-1` region
2. Update `template.yaml` parameter `DomainName`
3. Add Route53 record pointing to CloudFront

### Environment-Specific Deployments

Create separate stacks for dev/staging/prod:

```bash
sam deploy --stack-name git-captain-dev --parameter-overrides Environment=dev
sam deploy --stack-name git-captain-prod --parameter-overrides Environment=prod
```

### Enable API Gateway Caching

Update `template.yaml` API Gateway properties:
```yaml
CacheClusterEnabled: true
CacheClusterSize: '0.5'
```

## Support

For issues or questions:
- Check CloudWatch logs
- Review [lambda/README.md](lambda/README.md)
- Create an issue on GitHub

## Migration from EC2

If migrating from EC2:
1. Export data from EC2 (if any stateful data exists)
2. Deploy serverless stack
3. Update DNS/Load balancer to point to CloudFront
4. Monitor both systems during cutover
5. Decomission EC2 instance after verification
