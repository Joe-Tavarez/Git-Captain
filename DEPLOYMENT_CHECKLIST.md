# Git-Captain Serverless Deployment Checklist

## Pre-Deployment

### Prerequisites
- [ ] AWS Account created
- [ ] AWS CLI installed and configured (`aws configure`)
- [ ] AWS SAM CLI installed (`pip install aws-sam-cli`)
- [ ] Node.js 18+ installed
- [ ] GitHub OAuth App created

### GitHub OAuth App Setup
- [ ] Go to https://github.com/settings/developers
- [ ] Click "New OAuth App"
- [ ] Save Client ID
- [ ] Save Client Secret
- [ ] Note: You'll update callback URL after deployment

## Deployment Steps

### 1. Install Dependencies
```bash
cd lambda
npm install
cd ..
```
- [ ] Lambda dependencies installed

### 2. Build Application
```bash
sam build
```
- [ ] SAM build completed successfully

### 3. Deploy to AWS
```bash
# Option A: Guided (first time)
sam deploy --guided

# Option B: Automated script
.\deploy-serverless.ps1
```

**Provide during guided deployment:**
- [ ] Stack Name: `git-captain-serverless`
- [ ] AWS Region: `us-east-2` (or your choice)
- [ ] GitHub Client ID: `your-client-id`
- [ ] GitHub Client Secret: `your-client-secret`
- [ ] GitHub Org Name: `your-github-username`
- [ ] Confirm changeset: `Y`
- [ ] Allow IAM role creation: `Y`
- [ ] Save configuration: `Y`

### 4. Get Deployment Outputs
```bash
aws cloudformation describe-stacks --stack-name git-captain-serverless \
  --query "Stacks[0].Outputs" --output table
```

**Save these values:**
- [ ] API Gateway URL: `_____________________________`
- [ ] CloudFront URL: `_____________________________`
- [ ] S3 Bucket Name: `_____________________________`
- [ ] Secrets ARN: `_____________________________`

### 5. Upload Static Assets
```bash
aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --delete
```
- [ ] Static files uploaded to S3

### 6. Update GitHub OAuth App
- [ ] Go to your GitHub OAuth App settings
- [ ] Update Homepage URL: `https://YOUR-CLOUDFRONT-URL`
- [ ] Update Callback URL: `https://YOUR-CLOUDFRONT-URL/views/authenticated.html`
- [ ] Save changes

## Testing

### Initial Tests
- [ ] Visit CloudFront URL (may take 10-15 minutes for first access)
- [ ] Click "Login with GitHub"
- [ ] Authenticate successfully
- [ ] Can view repositories
- [ ] Can create a test branch
- [ ] Can search for branches
- [ ] Can delete test branch

### Health Check
```bash
curl https://YOUR-CLOUDFRONT-URL/prod/health
```
- [ ] Health check returns 200 OK

### API Tests
- [ ] All endpoints respond correctly
- [ ] OAuth flow works
- [ ] Branch operations work
- [ ] No CORS errors in browser console

## Post-Deployment

### Monitoring Setup
- [ ] Check CloudWatch Logs groups created:
  - `/aws/lambda/git-captain-health-check`
  - `/aws/lambda/git-captain-github-oauth`
  - `/aws/lambda/git-captain-github-status`
  - `/aws/lambda/git-captain-branch-operations`

### View Logs
```bash
aws logs tail /aws/lambda/git-captain-branch-operations --follow
```
- [ ] Logs accessible and showing activity

### Cost Monitoring
- [ ] Set up AWS Budget Alert for $5/month
- [ ] Monitor Lambda invocations in CloudWatch
- [ ] Check S3 storage usage

## GitHub Actions Setup (Optional)

### Add Secrets to GitHub Repository
Go to Settings → Secrets and variables → Actions

- [ ] `AWS_ACCESS_KEY_ID`
- [ ] `AWS_SECRET_ACCESS_KEY`
- [ ] `AWS_REGION`
- [ ] `GITHUB_CLIENT_ID`
- [ ] `GITHUB_CLIENT_SECRET`
- [ ] `GITHUB_ORG_NAME`

### Test Auto-Deploy
- [ ] Push to `main` or `feature/AWS` branch
- [ ] Check GitHub Actions workflow runs
- [ ] Verify deployment succeeds
- [ ] Test app after auto-deployment

## Documentation

- [ ] Update team documentation with CloudFront URL
- [ ] Share credentials securely (if team app)
- [ ] Document any custom configurations
- [ ] Add CloudFront URL to bookmarks

## Troubleshooting Checklist

If something doesn't work:

### OAuth Issues
- [ ] GitHub OAuth callback URL matches CloudFront URL exactly
- [ ] Secrets Manager contains correct credentials
- [ ] Check Lambda logs: `aws logs tail /aws/lambda/git-captain-github-oauth --follow`

### Static Assets Not Loading
- [ ] S3 sync completed successfully
- [ ] S3 bucket policy allows public read
- [ ] CloudFront distribution is "Deployed" (not "In Progress")
- [ ] Wait 15-20 minutes for CloudFront propagation

### API Errors
- [ ] Check Lambda function logs in CloudWatch
- [ ] Verify environment variables are set
- [ ] Check IAM role permissions
- [ ] Test Lambda function directly: `sam local invoke`

### CORS Errors
- [ ] API Gateway has CORS configured
- [ ] CloudFront is passing correct headers
- [ ] Check browser developer console for specific errors

## Success Criteria

Your deployment is successful when:
- ✅ CloudFront URL loads the application
- ✅ GitHub OAuth authentication works
- ✅ Can list repositories
- ✅ Can create branches
- ✅ Can search and delete branches
- ✅ No errors in CloudWatch logs
- ✅ Monthly cost < $3

## Next Steps After Success

### Optimization
- [ ] Review Lambda memory settings (512MB default)
- [ ] Adjust Lambda timeout if needed (30s default)
- [ ] Consider enabling API Gateway caching
- [ ] Set up CloudWatch alarms for errors

### Maintenance
- [ ] Review costs monthly
- [ ] Check CloudWatch logs weekly for errors
- [ ] Keep dependencies updated (`npm audit`)
- [ ] Monitor GitHub API rate limits

### Team Onboarding
- [ ] Share CloudFront URL with team
- [ ] Create user guide for team members
- [ ] Document any custom workflows
- [ ] Set up support channel for issues

## Rollback Plan

If you need to rollback:

```bash
# Delete the stack
sam delete --stack-name git-captain-serverless

# If needed, redeploy previous version
git checkout <previous-commit>
sam build && sam deploy
```

## Support Resources

- **AWS SAM Documentation**: https://docs.aws.amazon.com/serverless-application-model/
- **CloudWatch Logs**: https://console.aws.amazon.com/cloudwatch/
- **CloudFormation Console**: https://console.aws.amazon.com/cloudformation/
- **Project Documentation**: See SERVERLESS_DEPLOYMENT.md

---

## Deployment Completion

Date deployed: _________________

Deployed by: _________________

CloudFront URL: _________________

Notes:
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

**Congratulations! 🎉 Your Git-Captain serverless deployment is complete!**
