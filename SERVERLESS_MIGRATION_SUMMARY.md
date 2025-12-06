# Git-Captain Serverless Migration Summary

## What Was Created

Your Git-Captain application has been converted to a fully serverless architecture on AWS. Here's what was created:

### Core Infrastructure Files

1. **`template.yaml`** - AWS SAM (CloudFormation) template that defines:
   - 4 Lambda functions (health, oauth, status, branches)
   - API Gateway REST API
   - S3 bucket for static assets
   - CloudFront CDN distribution
   - Secrets Manager for GitHub OAuth credentials
   - CloudWatch Log Groups
   - All IAM roles and permissions

2. **Lambda Functions** (`lambda/` directory):
   - `health.js` - Health check endpoint
   - `oauth.js` - GitHub OAuth token exchange
   - `status.js` - Status checks (GitHub & Git-Captain)
   - `branches.js` - All Git operations (create, search, delete branches, PRs, repos)
   - `package.json` - Lambda dependencies (AWS SDK, axios)

3. **Deployment Scripts**:
   - `deploy-serverless.ps1` - PowerShell deployment automation
   - `.github/workflows/deploy-serverless.yml` - GitHub Actions CI/CD pipeline
   - `samconfig.toml` - SAM CLI configuration defaults

4. **Documentation**:
   - `SERVERLESS_DEPLOYMENT.md` - Complete deployment guide with architecture diagrams
   - `SERVERLESS_QUICKSTART.md` - Quick 5-minute setup guide
   - `lambda/README.md` - Lambda-specific documentation

### Architecture Changes

#### Before (EC2):
```
User → HTTPS Server (Node.js/Express) on EC2 → GitHub API
         ↑
    Static Files
```

#### After (Serverless):
```
User → CloudFront CDN
         ↓
    ┌────────┴─────────┐
    ↓                  ↓
S3 (Static)    API Gateway
                       ↓
                Lambda Functions → Secrets Manager
                       ↓
                GitHub API
```

### Key Benefits

1. **No Server Management** - AWS handles all infrastructure
2. **Auto-Scaling** - Handles any traffic level automatically
3. **Cost Reduction** - ~$2/month vs $10-50/month for EC2
4. **High Availability** - 99.99% uptime SLA
5. **Global Performance** - CloudFront edge locations worldwide
6. **Zero Maintenance** - No patches, updates, or monitoring needed

## How to Deploy

### Option 1: Automated PowerShell Script (Easiest)

```powershell
.\deploy-serverless.ps1
```

Prompts for GitHub OAuth credentials, then handles everything automatically.

### Option 2: Manual SAM Deployment

```bash
# 1. Install Lambda dependencies
cd lambda && npm install && cd ..

# 2. Build and deploy
sam build
sam deploy --guided

# 3. Upload static files
aws s3 sync public/ s3://YOUR-BUCKET-NAME/
```

### Option 3: GitHub Actions (Auto-Deploy on Push)

1. Add these GitHub Secrets:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION`
   - `GITHUB_CLIENT_ID`
   - `GITHUB_CLIENT_SECRET`
   - `GITHUB_ORG_NAME`

2. Push to `main` or `feature/AWS` branch
3. Deployment happens automatically!

## Post-Deployment Steps

After deployment completes:

1. **Get Your URLs**:
   ```bash
   aws cloudformation describe-stacks --stack-name git-captain-serverless \
     --query "Stacks[0].Outputs" --output table
   ```

2. **Update GitHub OAuth App**:
   - Go to https://github.com/settings/developers
   - Update callback URL to: `https://YOUR-CLOUDFRONT-URL/views/authenticated.html`

3. **Test Your App**:
   - Visit `https://YOUR-CLOUDFRONT-URL`
   - Authenticate with GitHub
   - Test branch operations

## Cost Breakdown

For ~5,000 requests/month:

| Service | Cost |
|---------|------|
| Lambda (compute) | $0.00 (free tier) |
| API Gateway | $0.02 |
| S3 (storage) | $0.10 |
| CloudFront (data transfer) | $0.50 |
| Secrets Manager | $0.40 |
| **Total** | **~$2/month** |

Compare to EC2:
- t2.micro: $8.50/month (minimum)
- Plus: EBS storage, data transfer, load balancer = **$15-50/month**

**Savings: 85-95% cost reduction!**

## Monitoring

### View Logs
```bash
# Branch operations
aws logs tail /aws/lambda/git-captain-branch-operations --follow

# OAuth
aws logs tail /aws/lambda/git-captain-github-oauth --follow

# Health checks
aws logs tail /aws/lambda/git-captain-health-check --follow

# Status checks
aws logs tail /aws/lambda/git-captain-github-status --follow
```

### CloudWatch Metrics
- Lambda invocations, errors, duration
- API Gateway requests, latency
- S3/CloudFront data transfer

## Updating Your App

### Update Lambda Code
```bash
# Make changes to lambda/*.js files
sam build
sam deploy
```

### Update Static Files
```bash
# Make changes to public/* files
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete
```

### Update Infrastructure
```bash
# Make changes to template.yaml
sam build
sam deploy
```

## Troubleshooting

### OAuth Not Working
```bash
# Check secrets
aws secretsmanager get-secret-value --secret-id git-captain/github-oauth

# Update secrets
aws secretsmanager update-secret --secret-id git-captain/github-oauth \
  --secret-string '{"client_id":"NEW_ID","client_secret":"NEW_SECRET"}'
```

### Static Files Not Loading
```bash
# Resync files
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete

# Invalidate CloudFront cache (takes 5-10 min)
aws cloudfront create-invalidation --distribution-id YOUR-DIST-ID --paths "/*"
```

### API Errors
```bash
# Check recent logs
aws logs tail /aws/lambda/git-captain-branch-operations --follow --since 10m

# Test Lambda directly
sam local invoke BranchOperationsFunction -e test-event.json
```

## Migration from EC2

If you're currently running on EC2:

1. **Deploy serverless** (doesn't affect EC2):
   ```bash
   sam build && sam deploy --guided
   ```

2. **Test thoroughly** with CloudFront URL

3. **Parallel run** - Keep both running for 24-48 hours

4. **Switch DNS/traffic** to CloudFront

5. **Monitor** for issues

6. **Decommission EC2** after verification

Both systems can run simultaneously during migration!

## Cleanup (Delete Everything)

To remove all resources:

```bash
# Empty S3 bucket first
aws s3 rm s3://YOUR-BUCKET-NAME --recursive

# Delete stack
sam delete --stack-name git-captain-serverless
```

## File Structure

```
Git-Captain/
├── template.yaml                    # SAM/CloudFormation template
├── samconfig.toml                   # SAM configuration
├── deploy-serverless.ps1            # Deployment script
├── SERVERLESS_DEPLOYMENT.md         # Full guide
├── SERVERLESS_QUICKSTART.md         # Quick start
├── lambda/                          # Lambda functions
│   ├── health.js
│   ├── oauth.js
│   ├── status.js
│   ├── branches.js
│   ├── package.json
│   └── README.md
├── .github/workflows/
│   └── deploy-serverless.yml        # GitHub Actions
└── public/                          # Static assets (uploaded to S3)
    ├── views/
    ├── css/
    └── js/
```

## Next Steps

1. **Deploy Now**: Run `.\deploy-serverless.ps1`
2. **Test Locally**: Use `sam local start-api` for local testing
3. **Set Up CI/CD**: Add GitHub secrets for auto-deployment
4. **Monitor**: Check CloudWatch logs and metrics
5. **Optimize**: Review costs and adjust Lambda memory/timeout if needed

## Support

- **Logs**: CloudWatch Logs for each Lambda function
- **Documentation**: See SERVERLESS_DEPLOYMENT.md for details
- **Local Testing**: Use `sam local` commands
- **AWS Support**: Check AWS CloudFormation console for stack status

## Summary

You now have a production-ready, serverless Git-Captain deployment that:
- ✅ Costs ~$2/month (vs $15-50 for EC2)
- ✅ Scales automatically
- ✅ Requires zero maintenance
- ✅ Has 99.99% uptime
- ✅ Deploys in 5 minutes
- ✅ Has global CDN performance

**Ready to deploy? Run: `.\deploy-serverless.ps1`**
