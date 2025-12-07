# AWS Lambda Deployment Guide for Git-Captain

## Prerequisites

1. **AWS CLI** - [Install Guide](https://aws.amazon.com/cli/)
   ```powershell
   aws --version
   ```

2. **AWS SAM CLI** - [Install Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
   ```powershell
   sam --version
   ```

3. **Node.js 18+** - Already installed ✓

4. **AWS Account with proper credentials configured**
   ```powershell
   aws configure
   ```

## Quick Start Deployment

### 1. Install Dependencies
```powershell
npm install
```

### 2. Deploy to AWS Lambda
```powershell
.\deploy-lambda.ps1 `
    -GitHubClientId "your_github_client_id" `
    -GitHubClientSecret "your_github_client_secret" `
    -GitHubOrgName "ConfusedDeer" `
    -Environment "prod" `
    -Region "us-east-2"
```

### 3. Update GitHub OAuth App
After deployment, update your GitHub OAuth App settings:
- Go to: https://github.com/settings/developers
- Update **Authorization callback URL** to the API URL from deployment output
- Format: `https://xxxxx.execute-api.us-east-2.amazonaws.com/prod/authenticated.html`

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTPS
       ▼
┌─────────────────┐
│  API Gateway    │
│  (REST API)     │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Lambda         │
│  (Node.js 18)   │
│  serverless-    │
│  http wrapper   │
└──────┬──────────┘
       │
       ├──► Secrets Manager (GitHub OAuth)
       ├──► CloudWatch Logs
       └──► GitHub API

```

## What Changed for Lambda?

### 1. **No More SSL/HTTPS Server**
   - API Gateway handles SSL/TLS
   - Removed `https.createServer()`
   - Removed SSL certificate files

### 2. **Serverless-HTTP Wrapper**
   - Added `serverless-http` package
   - Wraps Express app for Lambda events
   - File: `lambda-handler.js`

### 3. **Environment Variables**
   - Moved from `.env` to Lambda environment
   - Secrets stored in AWS Secrets Manager
   - No file system dependencies

### 4. **API Gateway Integration**
   - All routes work through API Gateway
   - Automatic HTTPS
   - Built-in rate limiting available

## Deployment Commands

### Deploy
```powershell
.\deploy-lambda.ps1 -GitHubClientId "xxx" -GitHubClientSecret "xxx"
```

### View Logs
```powershell
sam logs --stack-name git-captain-lambda --tail
```

### Test Locally
```powershell
sam local start-api --template sam-lambda.yaml
```

### Update Function
Just run the deploy script again - it will update the existing deployment.

### Delete Stack
```powershell
aws cloudformation delete-stack --stack-name git-captain-lambda --region us-east-2
```

## Cost Estimate

**AWS Lambda Free Tier:**
- 1M requests/month FREE
- 400,000 GB-seconds compute FREE

**Estimated Monthly Cost (beyond free tier):**
- Lambda: ~$0.20 per 1M requests
- API Gateway: ~$3.50 per 1M requests
- Secrets Manager: $0.40/month per secret
- CloudWatch Logs: ~$0.50/GB

**Total: ~$5-10/month for typical usage**

## Benefits of Lambda Deployment

✅ **Auto-scaling** - Handles 0 to thousands of requests automatically  
✅ **No server management** - AWS manages infrastructure  
✅ **Pay per use** - Only pay when code runs  
✅ **Built-in monitoring** - CloudWatch logs and metrics  
✅ **High availability** - Multi-AZ by default  
✅ **Security** - IAM roles, Secrets Manager, API Gateway  

## Troubleshooting

### Deployment fails with "sam: command not found"
Install AWS SAM CLI: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html

### "Unable to locate credentials"
Run: `aws configure` and enter your AWS Access Key ID and Secret Access Key

### Lambda timeout errors
Increase timeout in `sam-lambda.yaml`:
```yaml
Timeout: 60  # seconds
```

### Cold start issues
Consider enabling **Provisioned Concurrency** in the Lambda console for consistent performance.

## Monitoring

### View Lambda Metrics
```powershell
aws cloudwatch get-metric-statistics `
    --namespace AWS/Lambda `
    --metric-name Duration `
    --dimensions Name=FunctionName,Value=prod-git-captain `
    --start-time 2025-01-01T00:00:00Z `
    --end-time 2025-01-31T23:59:59Z `
    --period 3600 `
    --statistics Average
```

### Stream Logs in Real-Time
```powershell
sam logs --stack-name git-captain-lambda --region us-east-2 --tail
```

## Next Steps

1. ✅ Deploy to Lambda
2. ⬜ Set up custom domain with Route 53
3. ⬜ Add API Gateway caching for better performance
4. ⬜ Set up CI/CD with GitHub Actions
5. ⬜ Add API authentication/authorization
6. ⬜ Configure CloudWatch alarms

## Support

For issues or questions:
- Check CloudWatch logs first
- Review SAM build output
- Verify GitHub OAuth configuration
- Check IAM permissions

---

**Ready to deploy?** Run: `.\deploy-lambda.ps1 -GitHubClientId "xxx" -GitHubClientSecret "xxx"`
