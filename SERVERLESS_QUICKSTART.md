# Git-Captain Serverless - Quick Start

## Prerequisites
- AWS Account
- AWS CLI configured
- AWS SAM CLI installed: `pip install aws-sam-cli`
- GitHub OAuth App (create at https://github.com/settings/developers)

## 5-Minute Deployment

### 1. Install Dependencies
```bash
cd lambda
npm install
cd ..
```

### 2. Deploy (Automated Script)
```powershell
# Windows PowerShell
.\deploy-serverless.ps1

# You'll be prompted for:
# - GitHub OAuth Client ID
# - GitHub OAuth Client Secret
# - (Other settings use defaults)
```

### 3. Update GitHub OAuth App
After deployment, update your GitHub OAuth App with:
- **Homepage URL**: `https://YOUR-CLOUDFRONT-URL` (shown after deployment)
- **Callback URL**: `https://YOUR-CLOUDFRONT-URL/views/authenticated.html`

### 4. Access Your App
Visit the CloudFront URL shown after deployment completes.

## Manual Deployment

```bash
# 1. Install Lambda dependencies
cd lambda && npm install && cd ..

# 2. Build
sam build

# 3. Deploy (guided - first time)
sam deploy --guided

# 4. Sync static assets
aws s3 sync public/ s3://YOUR-BUCKET-NAME/

# 5. Get URLs
aws cloudformation describe-stacks --stack-name git-captain-serverless --query "Stacks[0].Outputs"
```

## Architecture

```
User Browser
    ↓
CloudFront (CDN)
    ↓
API Gateway → Lambda Functions → Secrets Manager
    ↓
S3 (Static Assets)
```

## Lambda Functions

| Function | Endpoint | Purpose |
|----------|----------|---------|
| `health.js` | `GET /health` | Health checks |
| `oauth.js` | `GET /gitCaptain/getToken` | GitHub OAuth |
| `status.js` | `GET /gitCaptain/checkGitHubStatus` | Status checks |
| `branches.js` | `POST /gitCaptain/*` | Git operations |

## Costs

**Estimated: < $2/month** for moderate usage
- Lambda: Free tier (1M requests free)
- API Gateway: ~$0.02/month
- S3 + CloudFront: ~$0.60/month
- Secrets Manager: $0.40/month

## Monitoring

```bash
# View logs
aws logs tail /aws/lambda/git-captain-branch-operations --follow

# View all stack outputs
aws cloudformation describe-stacks --stack-name git-captain-serverless
```

## Update Deployment

```bash
# Rebuild and redeploy
sam build && sam deploy

# Sync changed static files
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete
```

## GitHub Actions (Auto-Deploy)

Add these secrets to your GitHub repository:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION` (e.g., `us-east-2`)
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_ORG_NAME`

Push to `main` or `feature/AWS` branch to auto-deploy.

## Troubleshooting

### OAuth not working
```bash
# Check secrets
aws secretsmanager get-secret-value --secret-id git-captain/github-oauth

# Update if needed
aws secretsmanager update-secret --secret-id git-captain/github-oauth \
  --secret-string '{"client_id":"YOUR_ID","client_secret":"YOUR_SECRET"}'
```

### Static assets not loading
```bash
# Resync files
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation --distribution-id YOUR-DIST-ID --paths "/*"
```

### API errors
```bash
# Check logs
aws logs tail /aws/lambda/git-captain-branch-operations --follow --since 10m
```

## Cleanup

```bash
# Delete everything
aws s3 rm s3://YOUR-BUCKET-NAME --recursive
sam delete --stack-name git-captain-serverless
```

## Need Help?

1. Check CloudWatch logs
2. Review [SERVERLESS_DEPLOYMENT.md](SERVERLESS_DEPLOYMENT.md) for detailed guide
3. Check [lambda/README.md](lambda/README.md) for Lambda-specific info

## Key Benefits vs EC2

✅ **No server management** - Zero maintenance  
✅ **Auto-scaling** - Handles any load automatically  
✅ **Pay-per-use** - Only pay when requests come in  
✅ **99.99% uptime** - AWS managed infrastructure  
✅ **Global CDN** - Fast worldwide via CloudFront  
✅ **Cost effective** - ~$2/month vs $10+/month for EC2  

## Migration from EC2

If you're currently running on EC2:
1. Deploy serverless stack (doesn't affect EC2)
2. Test thoroughly with CloudFront URL
3. Update DNS to point to CloudFront
4. Monitor for 24-48 hours
5. Terminate EC2 instance

Both can run simultaneously during migration!
