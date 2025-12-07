# Git-Captain Serverless Deployment

This directory contains the AWS Lambda functions for the serverless version of Git-Captain.

## Architecture

Git-Captain is deployed as a serverless application using:
- **AWS Lambda**: Serverless compute for all API endpoints
- **API Gateway**: REST API to route requests to Lambda functions
- **S3 + CloudFront**: Static asset hosting (HTML, CSS, JS)
- **Secrets Manager**: Secure storage for GitHub OAuth credentials

## Lambda Functions

### 1. Health Check (`health.js`)
- **Endpoint**: `GET /health`
- **Purpose**: Health monitoring and status checks
- **No authentication required**

### 2. GitHub OAuth (`oauth.js`)
- **Endpoint**: `GET /gitCaptain/getToken`
- **Purpose**: Handle GitHub OAuth callback and token exchange
- **Requires**: GitHub OAuth authorization code

### 3. Status Checks (`status.js`)
- **Endpoints**: 
  - `GET /gitCaptain/checkGitHubStatus` - Check GitHub API status
  - `GET /gitCaptain/checkGitCaptainStatus` - Check Git-Captain status
- **No authentication required**

### 4. Branch Operations (`branches.js`)
- **Endpoints**:
  - `POST /gitCaptain/searchForRepos` - List user repositories
  - `POST /gitCaptain/createBranches` - Create new branch
  - `POST /gitCaptain/searchForBranch` - Search for specific branch
  - `POST /gitCaptain/searchForPR` - Search for pull requests
  - `POST /gitCaptain/logOff` - Revoke GitHub token
  - `DELETE /:appName/:webServ` - Delete branch
- **Requires**: GitHub OAuth token

## Deployment

### Prerequisites
1. AWS CLI configured with appropriate credentials
2. AWS SAM CLI installed (`pip install aws-sam-cli`)
3. Node.js 18.x
4. GitHub OAuth App credentials

### Initial Setup

1. **Install dependencies**:
   ```bash
   cd lambda
   npm install
   ```

2. **Deploy with SAM**:
   ```bash
   # From project root
   sam build
   sam deploy --guided
   ```

3. **Provide parameters during guided deployment**:
   - Stack Name: `git-captain-serverless`
   - AWS Region: `us-east-2` (or your preferred region)
   - GitHubClientId: Your GitHub OAuth Client ID
   - GitHubClientSecret: Your GitHub OAuth Client Secret
   - GitHubOrgName: Your GitHub username or organization
   - DomainName: (Optional) Custom domain

4. **Upload static assets to S3**:
   ```bash
   # Get S3 bucket name from stack outputs
   aws cloudformation describe-stacks --stack-name git-captain-serverless --query "Stacks[0].Outputs[?OutputKey=='StaticAssetsBucket'].OutputValue" --output text

   # Upload files
   aws s3 sync public/ s3://YOUR-BUCKET-NAME/ --exclude "*.md"
   ```

5. **Update GitHub OAuth App**:
   - Get CloudFront URL from stack outputs
   - Update GitHub OAuth App callback URL to: `https://YOUR-CLOUDFRONT-URL/views/authenticated.html`

### Subsequent Deployments

```bash
sam build && sam deploy
```

## Environment Variables

Lambda functions use these environment variables (configured in template.yaml):

- `NODE_ENV`: `production`
- `GITHUB_ORG_NAME`: GitHub organization/username
- `GIT_CAPTAIN_STATUS`: Service status
- `GIT_CAPTAIN_REASON`: Status reason
- `TIMEOUT_MINUTES`: Client timeout
- `SECRETS_ARN`: Secrets Manager ARN (auto-populated)

## Monitoring

### CloudWatch Logs
Each Lambda function has its own log group:
- `/aws/lambda/git-captain-health-check`
- `/aws/lambda/git-captain-github-oauth`
- `/aws/lambda/git-captain-github-status`
- `/aws/lambda/git-captain-branch-operations`

### Metrics
Monitor via CloudWatch:
- Function invocations
- Error rates
- Duration
- Throttles

## Cost Optimization

- Lambda functions: 512MB memory, 30s timeout
- CloudWatch logs: 7-day retention
- API Gateway caching: Disabled by default
- S3 + CloudFront: Pay per use

Estimated cost for moderate usage (1000 requests/month): **< $1/month**

## Security

- All secrets stored in AWS Secrets Manager
- HTTPS enforced via CloudFront
- CORS configured for cross-origin requests
- Rate limiting handled by API Gateway
- Lambda functions run with minimal IAM permissions

## Troubleshooting

### OAuth not working
1. Check GitHub OAuth App callback URL matches CloudFront URL
2. Verify Secrets Manager contains correct credentials
3. Check Lambda logs for OAuth function

### Static assets not loading
1. Verify S3 bucket has correct public read policy
2. Check CloudFront distribution status
3. Verify files uploaded to S3 with correct paths

### API errors
1. Check CloudWatch logs for specific Lambda function
2. Verify API Gateway routes are configured correctly
3. Test individual endpoints with curl or Postman

## Local Testing

Test Lambda functions locally with SAM:

```bash
sam local start-api
```

This starts a local API Gateway on http://localhost:3000

## Cleanup

To delete all resources:

```bash
sam delete --stack-name git-captain-serverless
```

Note: S3 buckets must be emptied before deletion.
