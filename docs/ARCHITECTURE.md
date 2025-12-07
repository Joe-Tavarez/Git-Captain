# Git-Captain v2.0 Architecture

## 🏗️ System Overview

Git-Captain is a modernized Node.js web application that provides a secure interface for GitHub repository management with OAuth authentication and comprehensive security middleware.

**🌐 Current Deployment**: Git-Captain is currently deployed as a monolithic serverless application on AWS Lambda with Function URL, featuring S3 audit logging. A microservices architecture with API Gateway is planned for future enhancement.

### Deployment Evolution
1. **v1.0** - Traditional on-premises Node.js server
2. **v2.0** - AWS EC2 with VPC, ALB, and enhanced security
3. **v2.1** (Current) - AWS Lambda monolithic with Function URL and S3 audit logging
4. **v2.2** (Planned) - AWS Lambda microservices with API Gateway, S3, and CloudFront CDN

See [AWS Architecture Documentation](./aws/AWS_ARCHITECTURE.md) for detailed cloud deployment information.

## 📍 Deployment Options

### ☁️ AWS Lambda Monolithic (Current)
**Single Lambda function with Function URL**

**Architecture Components**:
- **Single Lambda**: git-captain (Express app via serverless-http)
- **Function URL**: Public HTTPS endpoint with CORS
- **S3 Bucket**: Audit log storage (git-captain-logs-bucket)
- **S3 Logger Lambda**: Python function for S3 event processing
- **Environment Variables**: Client ID, secret, org name

**Benefits**:
- ✅ Simplest Lambda deployment
- ✅ No API Gateway costs
- ✅ Direct function invocation
- ✅ Audit logging to S3

**Limitations**:
- ⚠️ Limited routing flexibility
- ⚠️ All routes in single function
- ⚠️ Less granular scaling

---

### ☁️ AWS Lambda Microservices (Planned)
**Serverless architecture with API Gateway, S3, and CloudFront**

**Architecture Components**:
- **Lambda Functions**: 4 independent functions (health, oauth, status, branches)
- **API Gateway**: REST API with CORS and custom error handling
- **S3 Bucket**: Static asset hosting (HTML, CSS, JS, images)
- **CloudFront**: Global CDN for low-latency content delivery
- **Secrets Manager**: Encrypted OAuth credential storage
- **CloudWatch**: Centralized logging and monitoring

**Deployment Method**: AWS SAM (Serverless Application Model)
```bash
sam build && sam deploy --guided
```

**Benefits**:
- ✅ Auto-scaling with zero configuration
- ✅ Pay-per-request pricing model
- ✅ Built-in redundancy and failover
- ✅ Minimal operational maintenance
- ✅ Global CDN distribution
- ✅ Automatic SSL/TLS via CloudFront
- ✅ Independent function scaling
- ✅ Better separation of concerns

**Best For**: Variable traffic, cost optimization, rapid scaling, minimal ops overhead

---

### ☁️ AWS EC2 with VPC (Legacy)
**Traditional server deployment with comprehensive AWS infrastructure**
- ✅ No API Gateway costs
- ✅ Direct function invocation
- ✅ Audit logging to S3

**Limitations**:
- ⚠️ Limited routing flexibility
- ⚠️ All routes in single function
- ⚠️ Less granular scaling

---

### 🖥️ AWS EC2 with VPC (Legacy)
**Traditional server deployment with comprehensive AWS infrastructure**

**Architecture Components**:
- **EC2 Instance**: t3.medium in private subnet
- **Application Load Balancer**: Public-facing with SSL/TLS
- **Auto Scaling Group**: Multi-AZ redundancy
- **RDS PostgreSQL**: Optional database (private subnet)
- **NAT Gateway**: Internet access for private instances
- **CloudWatch**: Monitoring and log aggregation
- **VPC**: Custom networking with public/private subnets
- **Security Groups**: Firewall rules for traffic control

**Deployment Method**: CloudFormation template
```bash
aws cloudformation create-stack --template-body file://cloudformation/complete-stack.yaml
```

**Benefits**:
- ✅ No cold starts
- ✅ Full OS control
- ✅ Unlimited execution time
- ✅ Complex in-memory state management
- ✅ Direct database connections

**Best For**: Consistent high traffic, sub-100ms latency needs, long-running operations

---

### 🐳 Docker Container (Future Enhancement)
**Containerized deployment for portability**

**Planned Support**:
- Docker Compose for local development
- AWS ECS/Fargate for production
- Kubernetes deployment manifests
- Multi-stage builds for optimization

---

### 💻 On-Premises (Development)
**Local development and testing**

**Setup**:
- Node.js 18.x runtime
- Self-signed SSL certificates
- PM2 process management
- Local .env configuration

**Use Cases**:
- Development and testing
- Air-gapped environments
- Custom network requirements

## 📊 Current Architecture - Monolithic Lambda with Audit Logging

```mermaid
graph TB
    subgraph Client["<b>👤 Client Layer</b>"]
        User[🌐 Web Browser]
    end

    subgraph AWS["<b>☁️ AWS Lambda - us-east-2</b>"]
        subgraph Lambda["<b>⚡ Lambda Function: git-captain</b>"]
            FunctionURL[Function URL<br/>Public HTTPS Endpoint<br/>CORS Enabled]
            
            subgraph Handler["<b>🚀 Monolithic Handler</b>"]
                Express[Express.js App<br/>serverless-http wrapper]
                
                subgraph Routes["<b>🛤️ All Routes in One Function</b>"]
                    Health[GET /health<br/>Health Check]
                    Status[GET /gitCaptain/checkGitHubStatus<br/>GitHub Status]
                    Static[GET /static/*<br/>Static Files CSS/JS/Images]
                    Home[GET /<br/>Landing Page + client_id injection]
                    Auth[GET /authenticated.html<br/>OAuth Callback + client_id injection]
                    Config[GET /config.js<br/>Client Config]
                    Token[POST /gitCaptain/getToken<br/>OAuth Token Exchange]
                    Repos[POST /gitCaptain/searchForRepos<br/>List Repositories]
                    CreateBr[POST /gitCaptain/createBranches<br/>Create Branches + Audit]
                    DeleteBr[DELETE /gitCaptain/deleteBranches<br/>Delete Branches + Audit]
                    SearchBr[POST /gitCaptain/searchForBranch<br/>Search Branch]
                    SearchPR[POST /gitCaptain/searchForPR<br/>Search Pull Request]
                    LogOff[POST /gitCaptain/logOff<br/>Revoke Token]
                end
            end
            
            Runtime[Node.js 18.x Runtime<br/>512MB Memory<br/>30s Timeout]
        end
        
        subgraph Storage["<b>📦 Storage & Audit</b>"]
            S3[S3 Bucket<br/>git-captain-logs-bucket<br/>Audit Trail Storage]
            S3Logger[Lambda: git-captain-s3-logger<br/>Python 3.9<br/>Logs S3 uploads to CloudWatch]
        end
        
        subgraph Services["<b>🛠️ AWS Services</b>"]
            CW[CloudWatch Logs<br/>Function Logs + Audit Metadata]
            Env[Environment Variables<br/>GITHUB_CLIENT_ID<br/>GITHUB_CLIENT_SECRET<br/>GITHUB_ORG_NAME<br/>NODE_ENV]
        end
    end

    subgraph External["<b>🌍 External Services</b>"]
        GitHub[GitHub API<br/>api.github.com<br/>User repos, branches, PRs]
        OAuth[GitHub OAuth<br/>github.com/login/oauth<br/>Authorization & token exchange]
    end

    User -->|HTTPS| FunctionURL
    FunctionURL --> Express
    Express --> Health
    Express --> Status
    Express --> Static
    Express --> Home
    Express --> Auth
    Express --> Config
    Express --> Token
    Express --> Repos
    Express --> CreateBr
    Express --> DeleteBr
    Express --> SearchBr
    Express --> SearchPR
    Express --> LogOff
    
    Token --> OAuth
    Home --> Env
    Auth --> Env
    Config --> Env
    Repos --> GitHub
    CreateBr --> GitHub
    CreateBr -->|Write audit log| S3
    DeleteBr --> GitHub
    DeleteBr -->|Write audit log| S3
    SearchBr --> GitHub
    SearchPR --> GitHub
    LogOff --> OAuth
    
    S3 -->|S3 Event Trigger| S3Logger
    S3Logger -->|Log metadata| CW
    
    Handler --> Runtime
    Runtime --> CW

    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style AWS fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style Lambda fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style Handler fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Routes fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Services fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style External fill:#e8f5e9,stroke:#689f38,stroke-width:3px
    
    style User fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style FunctionURL fill:#fbc02d,stroke:#f57f17,stroke-width:2px,color:#000
    style Express fill:#66bb6a,stroke:#2e7d32,stroke-width:2px,color:#fff
    style Runtime fill:#9c27b0,stroke:#4a148c,stroke-width:2px,color:#fff
    style CW fill:#00acc1,stroke:#006064,stroke-width:2px,color:#fff
    style Env fill:#5e35b1,stroke:#311b92,stroke-width:2px,color:#fff
    style GitHub fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
    style OAuth fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
    
    style Health fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Status fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Static fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Home fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Auth fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Config fill:#4caf50,stroke:#1b5e20,stroke-width:1px,color:#fff
    style Token fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style Repos fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style CreateBr fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style DeleteBr fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style SearchBr fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style SearchPR fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
    style LogOff fill:#2196f3,stroke:#0d47a1,stroke-width:1px,color:#fff
```

## 🎯 Lambda Microservices Architecture (Future/Planned)

```mermaid
graph TB
    subgraph Client["<b>👤 Client Layer</b>"]
        User[🌐 Web Browser]
    end

    subgraph AWS["<b>☁️ AWS Infrastructure - us-east-2</b>"]
        subgraph CDN["<b>🌐 Content Delivery</b>"]
            CF[CloudFront Distribution<br/>Global Edge Caching<br/>HTTPS Enforced]
        end
        
        subgraph StaticHosting["<b>📦 Static Assets</b>"]
            S3Static[S3 Bucket<br/>git-captain-static<br/>Website Hosting<br/>Public Read Access]
            StaticContent[HTML/CSS/JS<br/>Images & Views<br/>Client Configuration]
        end
        
        subgraph Gateway["<b>🌐 API Gateway REST API</b>"]
            API[git-captain-api<br/>Stage: prod<br/>CORS Enabled<br/>Custom Error Responses]
            
            subgraph Routes["<b>🛤️ API Routes</b>"]
                R1["GET /health"]
                R2["GET /gitCaptain/getToken"]
                R3["GET /gitCaptain/checkGitHubStatus"]
                R4["GET /gitCaptain/checkGitCaptainStatus"]
                R5["POST /appName/webServ"]
                R6["DELETE /appName/webServ"]
            end
        end
        
        subgraph Lambdas["<b>⚡ Lambda Functions</b>"]
            HealthLambda["🏥 health-check<br/>Handler: health.handler<br/>Health monitoring<br/>Uptime & memory stats<br/>Node.js 18.x • 512MB • 30s"]
            
            OAuthLambda["🔐 github-oauth<br/>Handler: oauth.handler<br/>OAuth token exchange<br/>Secrets Manager integration<br/>Node.js 18.x • 512MB • 30s"]
            
            StatusLambda["📊 github-status<br/>Handler: status.handler<br/>GitHub API status<br/>Service health checks<br/>Node.js 18.x • 512MB • 30s"]
            
            BranchLambda["🌿 branch-operations<br/>Handler: branches.handler<br/>All branch operations<br/>Repo search & PR queries<br/>Token revocation<br/>Node.js 18.x • 512MB • 30s"]
        end
        
        subgraph Security["<b>🔐 Security & Configuration</b>"]
            Secrets[Secrets Manager<br/>git-captain/github-oauth<br/>Client ID & Secret<br/>Encrypted at rest]
            IAM[IAM Policies<br/>SecretsManagerReadWrite<br/>Lambda execution roles]
        end
        
        subgraph Monitoring["<b>📊 Observability</b>"]
            CW[CloudWatch Logs<br/>7-day retention<br/>Structured JSON logging]
            
            LogGroups[Log Groups<br/>/aws/lambda/git-captain-health-check<br/>/aws/lambda/git-captain-github-oauth<br/>/aws/lambda/git-captain-github-status<br/>/aws/lambda/git-captain-branch-operations]
        end
    end

    subgraph External["<b>🌍 External Services</b>"]
        GitHub[GitHub API<br/>api.github.com<br/>REST API v3]
        OAuth[GitHub OAuth<br/>github.com/login/oauth<br/>Authorization & token exchange]
    end

    User -->|HTTPS| CF
    CF -->|Static Assets| S3Static
    CF -->|API Requests /prod/*| API
    S3Static --> StaticContent
    
    API --> R1
    API --> R2
    API --> R3
    API --> R4
    API --> R5
    API --> R6
    
    R1 --> HealthLambda
    R2 --> OAuthLambda
    R3 --> StatusLambda
    R4 --> StatusLambda
    R5 --> BranchLambda
    R6 --> BranchLambda
    
    OAuthLambda --> Secrets
    OAuthLambda --> OAuth
    BranchLambda --> Secrets
    BranchLambda --> GitHub
    StatusLambda --> GitHub
    
    HealthLambda --> CW
    OAuthLambda --> CW
    StatusLambda --> CW
    BranchLambda --> CW
    CW --> LogGroups
    
    Secrets --> IAM
    OAuthLambda --> IAM
    BranchLambda --> IAM

    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style AWS fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style CDN fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style StaticHosting fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Gateway fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
    style Routes fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style Lambdas fill:#ffe0b2,stroke:#e65100,stroke-width:3px
    style Security fill:#ffebee,stroke:#c62828,stroke-width:2px
    style Monitoring fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    style External fill:#e8f5e9,stroke:#689f38,stroke-width:3px
    
    style User fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style CF fill:#00acc1,stroke:#006064,stroke-width:2px,color:#fff
    style S3Static fill:#ab47bc,stroke:#4a148c,stroke-width:2px,color:#fff
    style API fill:#43a047,stroke:#1b5e20,stroke-width:2px,color:#fff
    style HealthLambda fill:#26a69a,stroke:#004d40,stroke-width:2px,color:#fff
    style OAuthLambda fill:#fbc02d,stroke:#f57f17,stroke-width:2px,color:#000
    style StatusLambda fill:#1976d2,stroke:#0d47a1,stroke-width:2px,color:#fff
    style BranchLambda fill:#e91e63,stroke:#880e4f,stroke-width:2px,color:#fff
    style Secrets fill:#d32f2f,stroke:#b71c1c,stroke-width:2px,color:#fff
    style CW fill:#00897b,stroke:#004d40,stroke-width:2px,color:#fff
    style GitHub fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
    style OAuth fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
```

### Lambda Function Details

#### 🏥 Health Check Function (`git-captain-health-check`)
- **Handler**: `health.handler`
- **Purpose**: System health monitoring and diagnostics
- **Response Data**:
  - Service status (healthy/unhealthy)
  - Timestamp and uptime
  - Memory usage (heap used/total, RSS)
  - Environment (production/development)
  - Version information
- **No Authentication Required**
- **Endpoint**: `GET /health`

#### 🔐 GitHub OAuth Function (`git-captain-github-oauth`)
- **Handler**: `oauth.handler`
- **Purpose**: GitHub OAuth 2.0 token exchange
- **Process Flow**:
  1. Receives authorization code from GitHub
  2. Retrieves client credentials from Secrets Manager
  3. Exchanges code for access token
  4. Returns token to client for API operations
- **Security**: 
  - Secrets cached in Lambda execution context
  - IAM role with SecretsManagerReadWrite policy
  - CORS enabled for cross-origin requests
- **Endpoint**: `GET /gitCaptain/getToken?code={auth_code}`

#### 📊 GitHub Status Function (`git-captain-github-status`)
- **Handler**: `status.handler`
- **Purpose**: Service and GitHub API health checks
- **Endpoints**:
  - `GET /gitCaptain/checkGitHubStatus` - GitHub API status
  - `GET /gitCaptain/checkGitCaptainStatus` - Git-Captain service status
- **Response Data**:
  - API availability status
  - Response time metrics
  - Service operational status
  - Configuration validation
- **No Authentication Required**

#### 🌿 Branch Operations Function (`git-captain-branch-operations`)
- **Handler**: `branches.handler`
- **Purpose**: All GitHub repository and branch operations
- **Supported Operations**:
  - **Repository Search**: List user and organization repositories
  - **Branch Creation**: Create new branches from base branches
  - **Branch Search**: Find specific branches in repositories
  - **Branch Deletion**: Remove branches from repositories
  - **PR Search**: Query pull requests by various filters
  - **Token Revocation**: Logout and invalidate GitHub tokens
- **Authentication**: Requires valid GitHub OAuth token
- **Endpoints**:
  - `POST /{appName}/{webServ}` - Branch operations via path parameters
  - `DELETE /{appName}/{webServ}` - Branch deletion
- **GitHub API Integration**:
  - User-Agent: "Git-Captain"
  - Bearer token authentication
  - Comprehensive error handling
  - Rate limit awareness

### Static Asset Delivery

#### S3 + CloudFront Architecture
- **S3 Bucket**: `git-captain-static-{AWS::AccountId}`
  - Website hosting configuration
  - Public read access via bucket policy
  - CORS enabled for API integration
  - Serves: HTML pages, CSS stylesheets, JavaScript files, images

- **CloudFront Distribution**:
  - Global edge caching for low latency
  - HTTPS enforced (redirect-to-https)
  - Custom error responses (404 → /views/404.html)
  - Dual origin configuration:
    - **S3 Origin**: Static assets (default behavior)
    - **API Origin**: API Gateway for `/prod/*` paths
  - Cache behaviors:
    - Static assets: cached at edge locations
    - API requests: query strings and headers forwarded

### Security Architecture

#### Secrets Management
- **AWS Secrets Manager** stores GitHub OAuth credentials
- Secret name: `git-captain/github-oauth`
- JSON structure:
  ```json
  {
    "client_id": "...",
    "client_secret": "..."
  }
  ```
- Encrypted at rest with AWS KMS
- IAM policies restrict access to Lambda functions only
- Secrets cached in Lambda execution context for performance

#### IAM Policies
- Lambda execution roles with least-privilege access
- `SecretsManagerReadWrite` policy for OAuth and Branch functions
- CloudWatch Logs write permissions
- API Gateway invocation permissions

#### CORS Configuration
- API Gateway CORS enabled:
  - Allow-Methods: GET, POST, DELETE, OPTIONS
  - Allow-Headers: Content-Type, Authorization, X-Amz-Date, X-Api-Key
  - Allow-Origin: * (configure for production domains)
- Custom error responses include CORS headers
- S3 bucket CORS for cross-origin asset loading

### Monitoring & Logging

#### CloudWatch Integration
- **Log Groups** (7-day retention):
  - `/aws/lambda/git-captain-health-check`
  - `/aws/lambda/git-captain-github-oauth`
  - `/aws/lambda/git-captain-github-status`
  - `/aws/lambda/git-captain-branch-operations`

- **Log Structure**:
  - Structured JSON logging
  - Request/response tracking
  - Error stack traces
  - GitHub API interaction logs
  - OAuth flow tracing

- **Metrics Available**:
  - Invocation count and duration
  - Error rate and throttling
  - Memory utilization
  - Cold start frequency

### Deployment Configuration

#### SAM Template Parameters
- `GitHubClientId`: OAuth application client ID (NoEcho)
- `GitHubClientSecret`: OAuth application client secret (NoEcho)
- `GitHubOrgName`: Target GitHub organization/user (default: ConfusedDeer)
- `DomainName`: Optional custom domain configuration

#### Global Function Configuration
- **Runtime**: Node.js 18.x
- **Memory**: 512 MB
- **Timeout**: 30 seconds
- **Architecture**: x86_64
- **Environment Variables**:
  - `NODE_ENV=production`
  - `GITHUB_ORG_NAME` (from parameter)
  - `GIT_CAPTAIN_STATUS=up`
  - `GIT_CAPTAIN_REASON=Service is operational`
  - `TIMEOUT_MINUTES=25`
  - `RATE_LIMIT_WINDOW=60000` (1 minute)
  - `RATE_LIMIT_MAX=60` (60 requests per window)
  - `SESSION_TIMEOUT=1800000` (30 minutes)

#### Stack Outputs
- **ApiUrl**: API Gateway endpoint (`https://{api-id}.execute-api.{region}.amazonaws.com/prod`)
- **CloudFrontUrl**: CloudFront distribution domain name
- **StaticAssetsBucket**: S3 bucket name for asset uploads
- **SecretsArn**: Secrets Manager ARN for reference

## 🔧 Error Handling & Recovery Architecture

```mermaid
graph TB
    subgraph "Error Sources"
        ClientError[👤 Client Errors<br/>• Invalid input<br/>• Missing auth<br/>• Rate limits]
        ServerError[⚙️ Server Errors<br/>• Application bugs<br/>• Memory issues<br/>• Process crashes]
        NetworkError[🌐 Network Errors<br/>• GitHub API down<br/>• Timeout issues<br/>• DNS failures]
        SecurityError[🛡️ Security Errors<br/>• Invalid tokens<br/>• CORS violations<br/>• Attack attempts]
    end

    subgraph "Error Detection"
        Middleware[🔧 Middleware Layer<br/>Input validation<br/>Auth verification]
        TryCatch[🎯 Try-Catch Blocks<br/>Async error handling<br/>Promise rejection]
        StatusCheck[📊 Health Checks<br/>GitHub API status<br/>Service monitoring]
    end

    subgraph "Error Processing"
        ErrorHandler[⚡ Global Error Handler<br/>Express error middleware]
        
        subgraph "Error Classification"
            Validation[✅ Validation Errors<br/>400 Bad Request<br/>User-friendly messages]
            Auth[🔐 Authentication Errors<br/>401 Unauthorized<br/>Token refresh needed]
            Permission[🚫 Permission Errors<br/>403 Forbidden<br/>Scope insufficient]
            NotFound[❓ Not Found Errors<br/>404 Not Found<br/>Resource missing]
            RateLimit[⏱️ Rate Limit Errors<br/>429 Too Many Requests<br/>Retry after header]
            ServerErr[💥 Server Errors<br/>500 Internal Error<br/>Generic fallback]
        end
    end

    subgraph "Error Response"
        ResponseFormat[📝 Standardized Response<br/>JSON error format<br/>Consistent structure]
        Logging[📄 Error Logging<br/>Winston logger<br/>Stack traces<br/>Context data]
        UserFeedback[💬 User Feedback<br/>Helpful error messages<br/>Actionable guidance]
    end

    subgraph "Recovery Actions"
        Retry[🔄 Retry Logic<br/>Exponential backoff<br/>GitHub API retries]
        Fallback[🛡️ Fallback Responses<br/>Cached data<br/>Degraded service]
        Restart[🔃 Process Restart<br/>PM2 auto-restart<br/>Health recovery]
        Alert[🚨 Alert Escalation<br/>Critical error alerts<br/>Team notification]
    end

    ClientError --> Middleware
    ServerError --> TryCatch
    NetworkError --> StatusCheck
    SecurityError --> Middleware
    
    Middleware --> ErrorHandler
    TryCatch --> ErrorHandler
    StatusCheck --> ErrorHandler
    
    ErrorHandler --> Validation
    ErrorHandler --> Auth
    ErrorHandler --> Permission
    ErrorHandler --> NotFound
    ErrorHandler --> RateLimit
    ErrorHandler --> ServerErr
    
    Validation --> ResponseFormat
    Auth --> ResponseFormat
    Permission --> ResponseFormat
    NotFound --> ResponseFormat
    RateLimit --> ResponseFormat
    ServerErr --> ResponseFormat
    
    ResponseFormat --> Logging
    ResponseFormat --> UserFeedback
    
    Logging --> Retry
    Logging --> Fallback
    Logging --> Restart
    Logging --> Alert

    classDef source fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    classDef detect fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef process fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef classify fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef response fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef recovery fill:#e0f2f1,stroke:#00695c,stroke-width:2px

    class ClientError,ServerError,NetworkError,SecurityError source
    class Middleware,TryCatch,StatusCheck detect
    class ErrorHandler process
    class Validation,Auth,Permission,NotFound,RateLimit,ServerErr classify
    class ResponseFormat,Logging,UserFeedback response
    class Retry,Fallback,Restart,Alert recovery
```

## 🔄 Lambda Request Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    participant User as 👤 User
    participant Browser as 🌐 Browser
    participant CF as ☁️ CloudFront
    participant S3 as 📦 S3
    participant APIGW as 🌐 API Gateway
    participant Lambda as ⚡ Lambda
    participant Secrets as 🔐 Secrets Manager
    participant GitHub as 🐙 GitHub API
    participant CW as 📊 CloudWatch
    
    rect rgb(227, 242, 253)
    Note over User,CW: Static Asset Loading
    User->>Browser: Access Application URL
    Browser->>CF: GET https://cloudfront-url/
    CF->>S3: Fetch index.html
    S3->>CF: Return HTML
    CF->>Browser: Serve Cached Content
    Browser->>CF: Request CSS/JS/Images
    CF->>S3: Fetch Assets
    S3->>CF: Return Assets
    CF->>Browser: Serve from Edge Cache
    end
    
    rect rgb(255, 243, 224)
    Note over User,CW: OAuth Authentication Flow
    Browser->>GitHub: Redirect to OAuth
    GitHub->>Browser: Authorization Code
    Browser->>CF: GET /prod/gitCaptain/getToken?code=...
    CF->>APIGW: Route API Request
    APIGW->>Lambda: Invoke oauth.handler
    Lambda->>Lambda: Cold Start (if needed)
    Lambda->>Secrets: Retrieve OAuth Credentials
    Secrets->>Lambda: client_id & client_secret
    Lambda->>GitHub: POST /login/oauth/access_token
    GitHub->>Lambda: Access Token
    Lambda->>CW: Log OAuth Success
    Lambda->>APIGW: Return Token Response
    APIGW->>CF: API Response
    CF->>Browser: Token + User Info
    end
    
    rect rgb(232, 245, 233)
    Note over User,CW: Branch Operations
    User->>Browser: Create/Search/Delete Branch
    Browser->>CF: POST /prod/{appName}/{webServ}
    CF->>APIGW: Route to API
    APIGW->>Lambda: Invoke branches.handler
    Lambda->>Lambda: Validate Request
    Lambda->>Secrets: Get OAuth Credentials
    Secrets->>Lambda: Cached Secrets
    Lambda->>GitHub: API Request with Token
    Note over Lambda,GitHub: POST /repos/owner/repo/git/refs<br/>GET /repos/owner/repo/git/ref/heads/{branch}<br/>DELETE /repos/owner/repo/git/refs/heads/{branch}
    GitHub->>Lambda: Branch Data/Success
    Lambda->>CW: Log Operation
    Lambda->>APIGW: JSON Response
    APIGW->>CF: Forward Response
    CF->>Browser: Display Results
    Browser->>User: Success/Error Message
    end
    
    rect rgb(243, 229, 245)
    Note over User,CW: Health Check Monitoring
    Browser->>CF: GET /prod/health
    CF->>APIGW: Route Request
    APIGW->>Lambda: Invoke health.handler
    Lambda->>Lambda: Collect Metrics
    Lambda->>CW: Write Metrics
    Lambda->>APIGW: Health Status JSON
    APIGW->>Browser: 200 OK
    end
```

## 🔄 EC2 Request Flow Diagram (Legacy)

```mermaid
sequenceDiagram
    autonumber
    participant User as 👤 User
    participant Browser as 🌐 Browser
    participant IGW as 🌐 IGW
    participant SG as 🛡️ Security
    participant EC2 as 🖥️ EC2
    participant App as 🚀 App
    participant Security as 🛡️ Middleware
    participant NAT as 🔄 NAT
    participant GitHub as 🐙 GitHub
    participant RDS as 💾 Database
    participant CW as 📊 CloudWatch
    
    rect rgb(227, 242, 253)
    Note over User,CW: OAuth Authentication Flow
    User->>Browser: Access Application
    Browser->>IGW: HTTPS Request :3000
    IGW->>SG: Route to VPC
    SG->>EC2: Allow Traffic
    EC2->>App: PM2 → Node.js
    App->>Security: Check Security
    Security->>Security: Rate Limit ✓<br/>CORS ✓<br/>Headers ✓<br/>Validation ✓
    App->>CW: Log Request
    App->>Browser: Redirect to GitHub
    Browser->>GitHub: OAuth Request
    GitHub->>Browser: Auth Code
    Browser->>IGW: POST /getToken
    IGW->>EC2: Forward
    EC2->>App: Handle Token
    App->>NAT: Exchange Code
    NAT->>GitHub: Get Token
    GitHub->>NAT: Access Token
    NAT->>App: Token
    App->>CW: Log Auth
    App->>Browser: Success
    end
    
    rect rgb(232, 245, 233)
    Note over User,CW: Branch Operations
    User->>Browser: Create/Search/Delete
    Browser->>IGW: API Request
    IGW->>SG: Security Check
    SG->>EC2: Route Request
    EC2->>App: Handle
    App->>Security: Validate
    App->>NAT: GitHub API Call
    NAT->>GitHub: API Request
    GitHub->>NAT: Response
    NAT->>App: Data
    App->>RDS: Store/Query
    App->>CW: Log Operation
    App->>Browser: Results
    Browser->>User: Display
    end
```

## 🏢 Component Architecture

```mermaid
graph LR
    subgraph Frontend["<b>🎨 Frontend Layer</b>"]
        HTML[📄 HTML Templates<br/>index.html<br/>authenticated.html]
        CSS[🎨 CSS Styles<br/>styles.css]
        JS[⚡ JavaScript<br/>tools.js<br/>branchUtils.js<br/>viewUtils.js]
    end
    
    subgraph Backend["<b>🖥️ Backend - EC2: /opt/git-captain/</b>"]
        Server[🚀 server.js<br/>Main Application<br/>PM2 Managed]
        
        subgraph Core["<b>Core Modules</b>"]
            HTTP[🌐 httpClient.js<br/>Axios + GitHub API]
            MW[🛡️ middleware.js<br/>Security Stack]
            Val[✅ validation.js<br/>Input Schemas]
            Log[📝 logger.js<br/>Winston Logging]
            Cfg[⚙️ config.js<br/>.env Config]
        end
        
        SSL[🔒 SSL/TLS<br/>Self-signed Certs]
    end
    
    subgraph AWS["<b>☁️ AWS Services</b>"]
        RDS[(💾 PostgreSQL<br/>Private Subnet)]
        Lambda[⚡ Lambda<br/>S3 Logger]
        CW[📊 CloudWatch<br/>Logs & Metrics]
        S3[📦 S3 Bucket<br/>Log Storage]
    end
    
    subgraph External["<b>🌍 External APIs</b>"]
        GH[🐙 GitHub API<br/>Repositories<br/>Branches<br/>Pull Requests]
        OAuth[🔑 GitHub OAuth<br/>Authentication]
    end
    
    HTML --> Server
    CSS --> Server
    JS --> Server
    
    Server --> HTTP
    Server --> MW
    Server --> Val
    Server --> Log
    Server --> Cfg
    Server --> SSL
    Server --> RDS
    
    Log --> CW
    CW --> S3
    Lambda --> S3
    
    HTTP --> GH
    Server --> OAuth
    
    style Frontend fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style Backend fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style Core fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style AWS fill:#e1f5fe,stroke:#0288d1,stroke-width:3px
    style External fill:#e8f5e9,stroke:#689f38,stroke-width:3px
    
    style HTML fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style CSS fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style JS fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style Server fill:#ff9800,stroke:#e65100,stroke-width:2px,color:#fff
    style HTTP fill:#fbc02d,stroke:#f57f17,stroke-width:2px
    style MW fill:#fbc02d,stroke:#f57f17,stroke-width:2px
    style Val fill:#fbc02d,stroke:#f57f17,stroke-width:2px
    style Log fill:#fbc02d,stroke:#f57f17,stroke-width:2px
    style Cfg fill:#fbc02d,stroke:#f57f17,stroke-width:2px
    style SSL fill:#9c27b0,stroke:#4a148c,stroke-width:2px,color:#fff
    style RDS fill:#1976d2,stroke:#0d47a1,stroke-width:2px,color:#fff
    style Lambda fill:#00acc1,stroke:#006064,stroke-width:2px,color:#fff
    style CW fill:#00acc1,stroke:#006064,stroke-width:2px,color:#fff
    style S3 fill:#e91e63,stroke:#880e4f,stroke-width:2px,color:#fff
    style GH fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
    style OAuth fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
```

## 🔧 Technology Stack

```mermaid
graph TB
    subgraph "Frontend Technologies"
        HTML[📄 HTML5<br/>Semantic Markup]
        CSS3[🎨 CSS3<br/>Modern Styling]
        JS[⚡ Vanilla JavaScript<br/>ES6+ Features]
        jQuery[📚 jQuery 3.3.1<br/>DOM Manipulation]
    end

    subgraph "Backend Technologies"
        Node[🟢 Node.js<br/>Runtime Environment]
        Express[🚀 Express.js<br/>Web Framework]
        Axios[🌐 Axios<br/>HTTP Client]
        Winston[📝 Winston<br/>Logging Library]
    end

    subgraph "Security Technologies"
        Helmet[🛡️ Helmet<br/>Security Headers]
        CORS2[🔗 CORS<br/>Cross-Origin Control]
        RateLimit2[⏱️ express-rate-limit<br/>DDoS Protection]
        Validator[✅ express-validator<br/>Input Sanitization]
    end

    subgraph "Infrastructure"
        HTTPS[🔒 HTTPS/TLS<br/>Encryption]
        OAuth2[🔑 OAuth 2.0<br/>Authentication]
        Git[📚 Git<br/>Version Control]
        PM2[⚙️ PM2<br/>Process Management]
    end

    HTML --> Node
    CSS3 --> Node  
    JS --> Node
    jQuery --> Node
    
    Node --> Express
    Express --> Axios
    Express --> Winston
    Express --> Helmet
    Express --> CORS2
    Express --> RateLimit2
    Express --> Validator
    
    Express --> HTTPS
    Express --> OAuth2
    
    classDef frontend fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef backend fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef security fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef infra fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class HTML,CSS3,JS,jQuery frontend
    class Node,Express,Axios,Winston backend
    class Helmet,CORS2,RateLimit2,Validator security
    class HTTPS,OAuth2,Git,PM2 infra
```

## 🔗 Data Flow & API Architecture

```mermaid
graph TD
    subgraph "Client Layer"
        UI[🖥️ User Interface<br/>HTML5 + CSS3 + JS]
        AJAX[📡 AJAX Calls<br/>jQuery + Axios patterns]
    end

    subgraph "API Gateway Layer"
        Router[🚏 Express Router<br/>Endpoint routing]
        Middleware[🔧 Middleware Chain<br/>Security → Validation → Auth]
    end

    subgraph "Business Logic"
        TokenMgr[🎫 Token Manager<br/>OAuth token handling]
        RepoMgr[📦 Repository Manager<br/>GitHub repo operations]
        BranchMgr[🌿 Branch Manager<br/>Branch CRUD operations]
        PRMgr[🔄 PR Manager<br/>Pull request queries]
    end

    subgraph "External APIs"
        OAuth[🔑 GitHub OAuth API<br/>https://github.com/login/oauth]
        RepoAPI[📚 Repository API<br/>GET /user/repos]
        BranchAPI[🌿 Git References API<br/>GET/POST/DELETE /repos/owner/repo/git/refs]
        PRAPI[🔄 Pull Requests API<br/>GET /repos/owner/repo/pulls]
    end

    UI --> AJAX
    AJAX --> Router
    Router --> Middleware
    
    Middleware --> TokenMgr
    Middleware --> RepoMgr
    Middleware --> BranchMgr
    Middleware --> PRMgr
    
    TokenMgr --> OAuth
    RepoMgr --> RepoAPI
    BranchMgr --> BranchAPI
    PRMgr --> PRAPI

    classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef gateway fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef business fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class UI,AJAX client
    class Router,Middleware gateway
    class TokenMgr,RepoMgr,BranchMgr,PRMgr business
    class OAuth,RepoAPI,BranchAPI,PRAPI external
```

## 📋 API Endpoints Overview

### Lambda Deployment (Current)

| Endpoint | Method | Lambda Function | Purpose | Authentication |
|----------|--------|----------------|---------|----------------|
| `/health` | GET | health-check | Health monitoring | None |
| `/gitCaptain/getToken` | GET | github-oauth | OAuth token exchange | OAuth code |
| `/gitCaptain/checkGitHubStatus` | GET | github-status | Check GitHub API status | None |
| `/gitCaptain/checkGitCaptainStatus` | GET | github-status | Check service status | None |
| `/{appName}/{webServ}` | POST | branch-operations | Branch operations (create/search) | GitHub token |
| `/api/v1/{appName}/{webServ}` | POST | branch-operations | API v1 branch operations | GitHub token |
| `/{appName}/{webServ}` | DELETE | branch-operations | Delete branch | GitHub token |
| `/{appName}/{webServ}` | GET | branch-operations | Get branch info | GitHub token |

**Note**: All API endpoints are prefixed with `/prod` via API Gateway stage.

### EC2 Deployment (Legacy)

| Endpoint | Method | Purpose | Rate Limit | Authentication |
|----------|--------|---------|------------|----------------|
| `/` | GET | Landing page | General | None |
| `/gitCaptain/getToken` | GET/POST | OAuth token exchange | Auth (300/5min) | OAuth code |
| `/authenticated.html` | GET | OAuth callback page | General | None |
| `/gitCaptain/createBranch` | POST | Create new branch | Auth (300/5min) | GitHub token |
| `/gitCaptain/searchForBranch` | POST | Search branches | Auth (300/5min) | GitHub token |
| `/gitCaptain/deleteBranch` | POST | Delete branch | Auth (300/5min) | GitHub token |
| `/gitCaptain/searchForRepos` | POST | Search repositories | Auth (300/5min) | GitHub token |
| `/static/*` | GET | Static assets | General | None |

## 🔄 Architecture Comparison: Lambda vs EC2

| Aspect | Lambda Microservices | EC2 Traditional |
|--------|---------------------|-----------------|
| **Deployment Model** | Serverless, event-driven | Always-on server process |
| **Scaling** | Automatic, per-request | Manual or Auto Scaling Group |
| **Cost Model** | Pay-per-invocation + duration | Continuous instance cost |
| **Cold Start** | 100-500ms initial latency | No cold starts |
| **Maintenance** | Minimal, AWS-managed runtime | OS patching, PM2 management |
| **Static Assets** | S3 + CloudFront CDN | Express static middleware |
| **OAuth Secrets** | Secrets Manager (encrypted) | .env file on instance |
| **Logging** | CloudWatch Logs (7-day retention) | Winston file logs (14-day rotation) |
| **Monitoring** | CloudWatch metrics (automatic) | Custom monitoring + PM2 |
| **Failover** | Built-in multi-AZ redundancy | Requires ALB + multi-instance |
| **Request Timeout** | 30 seconds (Lambda limit) | Configurable (unlimited) |
| **Concurrency** | 1000 concurrent executions (default) | Limited by instance size |
| **State Management** | Stateless (function lifecycle) | Can maintain in-memory state |
| **GitHub API Rate** | Shared across invocations | Per-instance IP address |
| **SSL/TLS** | AWS-managed (CloudFront) | Self-signed or Let's Encrypt |
| **CORS Handling** | API Gateway + S3 CORS | Express middleware |
| **Security Groups** | Not applicable | VPC security groups |
| **NAT Gateway** | Not required | Required for private subnets |
| **Database** | No persistent storage | Optional RDS PostgreSQL |
| **Health Checks** | Lambda endpoint | Express endpoint + PM2 |
| **Rollback** | SAM deploy with previous version | Manual git revert + restart |
| **Development** | Local SAM CLI testing | Standard Node.js debugging |
| **CI/CD** | AWS CodePipeline, GitHub Actions | Traditional deployment scripts |

### When to Use Lambda
✅ Variable traffic patterns  
✅ Cost optimization for low/medium traffic  
✅ Quick scaling requirements  
✅ Minimal operational overhead  
✅ Event-driven workflows  
✅ Global CDN distribution needed  

### When to Use EC2
✅ Consistent high traffic  
✅ Sub-100ms latency requirements  
✅ Long-running operations (>30s)  
✅ Complex in-memory caching  
✅ Direct database connections  
✅ Full OS-level control needed

## 🔒 Security Architecture

```mermaid
graph TB
    subgraph "Security Layers"
        HTTPS[🔒 HTTPS/TLS<br/>Encryption in Transit]
        Helmet[🛡️ Helmet Middleware<br/>Security Headers]
        CORS[🔗 CORS Policy<br/>Cross-Origin Control]
        RateLimit[⏱️ Rate Limiting<br/>DDoS Protection]
    end

    subgraph "Authentication & Authorization"
        OAuth[🔑 GitHub OAuth 2.0<br/>Authorization Code Flow]
        Token[🎫 Access Token<br/>Bearer Authentication]
        Scope[🎯 Scope Validation<br/>Least Privilege]
    end

    subgraph "Input Security"
        Validation[✅ Input Validation<br/>express-validator]
        Sanitization[🧹 Data Sanitization<br/>XSS Prevention]
        Schema[📋 Request Schema<br/>Joi Validation]
    end

    subgraph "Monitoring & Logging"
        Logger[📝 Security Logging<br/>Winston + File Rotation]
        Audit[📊 Audit Trail<br/>User Actions]
        Alerts[🚨 Security Events<br/>Failed Auth Attempts]
    end

    HTTPS --> Helmet
    Helmet --> CORS
    CORS --> RateLimit
    RateLimit --> OAuth
    OAuth --> Token
    Token --> Scope
    Scope --> Validation
    Validation --> Sanitization
    Sanitization --> Schema
    
    Logger --> Audit
    Audit --> Alerts

    classDef security fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef auth fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef input fill:#e3f2fd,stroke:#0277bd,stroke-width:2px
    classDef monitor fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class HTTPS,Helmet,CORS,RateLimit security
    class OAuth,Token,Scope auth
    class Validation,Sanitization,Schema input
    class Logger,Audit,Alerts monitor
```

## 🗂️ Project Structure

```
Git-Captain/
├── 📁 lambda/                        # ⚡ AWS Lambda Functions (Serverless)
│   ├── 🏥 health.js                 # Health check Lambda handler
│   ├── 🔐 oauth.js                  # GitHub OAuth token exchange
│   ├── 📊 status.js                 # Status check handlers
│   ├── 🌿 branches.js               # Branch operations (main handler)
│   ├── 🐍 s3-upload-logger.py       # S3 audit log processor (Python)
│   ├── 📦 package.json              # Lambda dependencies
│   └── 📖 README.md                 # Lambda deployment guide
├── 📁 controllers/                   # 🖥️ Backend Core (EC2/Traditional)
│   ├── 🔧 server.js                 # Main Express application server
│   ├── 🌐 httpClient.js             # Axios-based HTTP client
│   ├── 🛡️ middleware.js             # Security middleware stack
│   ├── ✅ validation.js             # Input validation schemas
│   ├── 📝 logger.js                 # Winston logging configuration
│   ├── ⚙️ config.js                 # Environment & app configuration
│   └── 🔒 security.js               # Security utilities
├── 📁 public/                       # 🎨 Frontend Assets (S3/Static)
│   ├── 📁 css/                      # Stylesheets
│   │   └── 🎨 styles.css           # Main UI styling
│   ├── 📁 js/                       # Client-side JavaScript
│   │   ├── 🔧 tools.js              # API interaction utilities
│   │   ├── 🌿 branchUtils.js        # Branch operation helpers
│   │   └── ⚙️ viewUtils.js          # UI manipulation utilities
│   ├── 📁 images/                   # Static images & favicon
│   └── 📁 views/                    # HTML templates
│       ├── 📄 index.html            # Landing page
│       └── 🔐 authenticated.html    # OAuth callback page
├── 📁 cloudformation/               # ☁️ CloudFormation Templates
│   ├── complete-stack.yaml          # Full stack deployment
│   ├── ec2-alb-autoscaling.yaml     # EC2 with load balancing
│   ├── lambda-s3-logging.yaml       # Lambda + S3 audit system
│   ├── cloudwatch-monitoring.yaml   # Monitoring & alerting
│   ├── rds.yaml                     # RDS PostgreSQL database
│   └── waf.yaml                     # Web Application Firewall
├── 📁 terraform/                    # 🔧 Terraform IaC (Alternative)
│   ├── main.tf                      # Main Terraform configuration
│   ├── outputs.tf                   # Output definitions
│   └── README.md                    # Terraform usage guide
├── 📁 docs/                         # 📚 Documentation
│   ├── 📋 ARCHITECTURE.md           # System architecture (this file)
│   ├── 🚀 DEPLOYMENT.md             # Deployment guide
│   ├── 🔒 SECURITY.md               # Security documentation
│   └── 📁 aws/                      # AWS-specific documentation
├── 📁 logs/                         # 📄 Application logs (EC2 only)
│   ├── 📄 git-captain-YYYY-MM-DD.log # Daily application logs
│   └── 🚨 git-captain-errors-YYYY-MM-DD.log # Error logs
├── 📁 test/                         # 🧪 Test suites
│   └── 🧪 security.test.js          # Security tests
├── 📁 scripts/                      # ⚙️ Utility scripts
│   └── ⚙️ setup.js                  # Environment setup
├── 📁 boto3-scripts/                # 🐍 Python AWS automation
│   ├── ec2_operations.py            # EC2 management scripts
│   ├── s3_operations.py             # S3 bucket operations
│   └── lambda_test.py               # Lambda testing utilities
├── 📁 ec2-scripts/                  # 🖥️ EC2 deployment scripts
│   ├── user-data.sh                 # EC2 initialization script
│   ├── health-check.sh              # Health monitoring script
│   └── app-update.sh                # Application update automation
├── 🔐 .env                          # Environment variables (EC2)
├── ☁️ template.yaml                  # AWS SAM template (Lambda deployment)
├── ☁️ samconfig.toml                 # SAM CLI configuration
├── 📦 package.json                  # Node.js dependencies (EC2)
├── 📋 MODULE_UPDATES.md             # Modernization changelog
├── 📖 README.md                     # Project overview
├── ⚙️ SETUP.md                      # Setup instructions
├── ☁️ AWS_DEPLOYMENT_CHECKLIST.md   # AWS deployment guide
├── ☁️ AWS_QUICK_REFERENCE.md        # AWS resource reference
├── ☁️ LAMBDA_DEPLOYMENT.md          # Lambda-specific deployment
├── ☁️ SERVERLESS_QUICKSTART.md      # Serverless quick start
└── 📄 LICENSE                       # MIT License
```

### Directory Purpose Summary

#### Lambda Functions (`lambda/`)
AWS Lambda serverless functions for scalable, event-driven architecture:
- **health.js**: Health monitoring endpoint
- **oauth.js**: GitHub OAuth 2.0 authentication
- **status.js**: Service status checks
- **branches.js**: Main handler for all branch operations
- **s3-upload-logger.py**: Python-based S3 audit log processor

#### Controllers (`controllers/`)
Traditional server-based backend for EC2 deployments:
- Express.js server with comprehensive middleware
- Security, validation, logging layers
- Direct GitHub API integration

#### Public Assets (`public/`)
Frontend static files served via:
- **Lambda**: S3 + CloudFront CDN
- **EC2**: Express static file serving

#### Infrastructure as Code
- **cloudformation/**: AWS CloudFormation YAML templates
- **terraform/**: Terraform HCL configurations
- **template.yaml**: AWS SAM (Serverless Application Model)

#### Deployment Scripts
- **ec2-scripts/**: EC2-specific deployment automation
- **boto3-scripts/**: Python AWS SDK automation
- **PowerShell scripts**: Windows deployment helpers

## 🔄 OAuth Flow Architecture

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant B as 🌐 Browser
    participant G as 🐙 GitHub OAuth
    participant A as 🚀 Git-Captain
    participant API as 📡 GitHub API

    Note over U,API: Complete OAuth 2.0 Authorization Code Flow
    
    U->>B: 1. Click "Login with GitHub"
    B->>G: 2. Redirect to OAuth authorization
    Note over G: User authorizes application<br/>with repo scope
    G->>B: 3. Redirect with authorization code
    B->>A: 4. POST /gitCaptain/getToken<br/>{code, client_id, client_secret}
    
    Note over A: Security validation:<br/>• Rate limiting<br/>• Input validation<br/>• CORS check
    
    A->>G: 5. Exchange code for access token
    G->>A: 6. Return access token + metadata
    A->>B: 7. Success response with token
    
    Note over U,API: Authenticated GitHub Operations
    
    U->>B: 8. Branch operation request
    B->>A: 9. POST /gitCaptain/{operation}<br/>Authorization: Bearer token
    A->>API: 10. GitHub API call with token
    API->>A: 11. API response
    A->>B: 12. Formatted response
    B->>U: 13. Display results
```

## 🛡️ Enhanced Security Flow

```mermaid
graph TB
    subgraph "Request Journey"
        Request[📨 Incoming Request]
        Response[📤 Response]
    end

    subgraph "Security Pipeline"
        SSL[🔒 SSL/TLS Termination<br/>Certificate Validation]
        RateLimit[⏱️ Rate Limiting<br/>• General: 200/15min<br/>• Auth: 300/5min<br/>• IP-based tracking]
        CORS[🔗 CORS Validation<br/>• Origin whitelist<br/>• Method validation<br/>• Credentials handling]
        Helmet[🛡️ Security Headers<br/>• CSP enforcement<br/>• XSS protection<br/>• Frame options]
        Auth[🔐 Authentication<br/>• OAuth token validation<br/>• Scope verification<br/>• Rate limit by user]
        Validation[✅ Input Validation<br/>• Schema validation<br/>• Sanitization<br/>• Type checking]
        Audit[📝 Security Audit<br/>• Request logging<br/>• Failed auth tracking<br/>• Anomaly detection]
    end

    subgraph "Threat Mitigation"
        DDoS[🚫 DDoS Protection]
        XSS[🚫 XSS Prevention]
        CSRF[🚫 CSRF Protection]
        Injection[🚫 Injection Prevention]
    end

    Request --> SSL
    SSL --> RateLimit
    RateLimit --> CORS
    CORS --> Helmet
    Helmet --> Auth
    Auth --> Validation
    Validation --> Audit
    Audit --> Response

    RateLimit -.-> DDoS
    Helmet -.-> XSS
    CORS -.-> CSRF
    Validation -.-> Injection

    classDef security fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef threat fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    classDef flow fill:#e8f5e8,stroke:#388e3c,stroke-width:2px

    class SSL,RateLimit,CORS,Helmet,Auth,Validation,Audit security
    class DDoS,XSS,CSRF,Injection threat
    class Request,Response flow
```

### Rate Limiting Strategy
- **General endpoints**: 200 requests per 15 minutes
- **Authenticated endpoints**: 300 requests per 5 minutes  
- **Static assets**: Unlimited (served efficiently)

### Caching Strategy
- Static assets served with appropriate cache headers
- GitHub API responses cached temporarily to reduce API calls
- SSL termination at reverse proxy level for performance

### Scalability Design
- Stateless application design for horizontal scaling
- Session data stored in GitHub tokens (no server-side sessions)
- Logging designed for distributed environments
- Process management ready (PM2 compatible)

## 🔧 Configuration Management

### Environment Variables (.env)
```bash
# Server Configuration
HTTPS_PORT=3000
HTTP_PORT=3001

# GitHub OAuth
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_CALLBACK_URL=https://yourdomain.com/authenticated.html

# Application Settings
ORG_NAME=your-github-org
REPO_NAME=your-repo-name

# Security
SSL_KEY_PATH=./controllers/theKey.key
SSL_CERT_PATH=./controllers/theCert.cert

# Logging
LOG_LEVEL=info
LOG_MAX_SIZE=10m
LOG_MAX_FILES=14
```

### Runtime Configuration (config.js)
- Environment variable validation using Joi
- Default value fallbacks for development
- SSL certificate loading and validation
- GitHub API endpoint configuration

## 🚀 Deployment Architecture

```mermaid
graph TB
    subgraph "Internet"
        Users[👥 Users<br/>Global Access]
        CDN[🌐 CDN<br/>CloudFlare/AWS CloudFront<br/>Static Asset Delivery]
    end

    subgraph "Edge Layer"
        WAF[🛡️ Web Application Firewall<br/>DDoS Protection<br/>Attack Filtering]
        LB[⚖️ Load Balancer<br/>nginx/HAProxy/ALB<br/>SSL Termination]
    end

    subgraph "Application Tier"
        subgraph "Production Cluster"
            App1[🚀 Git-Captain Instance 1<br/>PM2 Cluster Mode<br/>Port 3000]
            App2[🚀 Git-Captain Instance 2<br/>PM2 Cluster Mode<br/>Port 3000]
            App3[🚀 Git-Captain Instance 3<br/>PM2 Cluster Mode<br/>Port 3000]
        end
        
        subgraph "Configuration"
            Env[🔧 Environment Config<br/>.env files<br/>Secrets management]
            SSL[🔒 SSL Certificates<br/>Let's Encrypt/Custom<br/>Auto-renewal]
        end
    end

    subgraph "Monitoring & Operations"
        Monitor[📊 Process Monitor<br/>PM2 Dashboard<br/>Health Checks]
        Logs[📄 Centralized Logging<br/>Winston → ELK Stack<br/>Log Aggregation]
        Metrics[📈 Application Metrics<br/>Prometheus + Grafana<br/>Performance Monitoring]
        Alerts[🚨 Alerting System<br/>PagerDuty/Slack<br/>Error Notifications]
    end

    subgraph "External Dependencies"
        GitHub[🐙 GitHub API<br/>api.github.com<br/>OAuth + REST API]
        DNS[� DNS Provider<br/>Route 53/CloudFlare<br/>Domain Management]
    end

    subgraph "Security & Backup"
        Backup[💾 Configuration Backup<br/>Git Repository<br/>Infrastructure as Code]
        Secrets[🔐 Secrets Management<br/>AWS Secrets Manager<br/>HashiCorp Vault]
    end

    Users --> CDN
    Users --> WAF
    WAF --> LB
    LB --> App1
    LB --> App2
    LB --> App3
    
    App1 --> Env
    App2 --> Env
    App3 --> Env
    
    App1 --> SSL
    App2 --> SSL
    App3 --> SSL
    
    Monitor --> App1
    Monitor --> App2
    Monitor --> App3
    
    App1 --> Logs
    App2 --> Logs
    App3 --> Logs
    
    Logs --> Metrics
    Metrics --> Alerts
    
    App1 --> GitHub
    App2 --> GitHub
    App3 --> GitHub
    
    DNS --> LB
    CDN --> DNS
    
    Env --> Secrets
    App1 --> Backup
    
    classDef users fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef edge fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef app fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef config fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef monitor fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef security fill:#ffebee,stroke:#d32f2f,stroke-width:2px

    class Users,CDN users
    class WAF,LB edge
    class App1,App2,App3 app
    class Env,SSL config
    class Monitor,Logs,Metrics,Alerts monitor
    class GitHub,DNS external
    class Backup,Secrets security
```

## 🧪 Testing Strategy

### Security Testing
- Input validation boundary testing
- Authentication bypass attempts  
- Rate limiting verification
- XSS and injection attack prevention

### Integration Testing  
- GitHub OAuth flow end-to-end
- API endpoint response validation
- Error handling and recovery
- SSL/TLS configuration verification

### Performance Testing
- Load testing with realistic user patterns
- Rate limit threshold validation
- Memory leak detection during extended runs
- GitHub API rate limit handling

## 📈 Monitoring & Observability

```mermaid
graph TB
    subgraph "Application Monitoring"
        App[🚀 Git-Captain App<br/>Express Server]
        
        subgraph "Metrics Collection"
            ReqMetrics[📊 Request Metrics<br/>• Response times<br/>• Status codes<br/>• Endpoint usage]
            AuthMetrics[🔐 Auth Metrics<br/>• Login success/failure<br/>• Token validation<br/>• OAuth flow timing]
            APIMetrics[📡 API Metrics<br/>• GitHub API calls<br/>• Rate limit usage<br/>• Error rates]
            PerfMetrics[⚡ Performance Metrics<br/>• Memory usage<br/>• CPU utilization<br/>• Event loop lag]
        end
    end

    subgraph "Logging Pipeline"
        Logger[📝 Winston Logger<br/>Structured JSON logs]
        
        subgraph "Log Types"
            AccessLogs[🌐 Access Logs<br/>HTTP requests<br/>Morgan format]
            ErrorLogs[❌ Error Logs<br/>Application errors<br/>Stack traces]
            SecurityLogs[🛡️ Security Logs<br/>Auth failures<br/>Rate limit hits<br/>Suspicious activity]
            AuditLogs[📋 Audit Logs<br/>User actions<br/>API operations<br/>Config changes]
        end
        
        FileRotation[🔄 Log Rotation<br/>Daily rotation<br/>14-day retention<br/>Compression]
    end

    subgraph "Alerting & Analysis"
        LogAggregation[📊 Log Aggregation<br/>ELK Stack<br/>Centralized search]
        Dashboard[📈 Dashboards<br/>Grafana/Kibana<br/>Real-time views]
        Alerts[🚨 Alerting Rules<br/>Error thresholds<br/>Performance SLAs<br/>Security events]
        
        subgraph "Alert Channels"
            Email[📧 Email Alerts<br/>Critical errors]
            Slack[💬 Slack Integration<br/>Team notifications]
            PagerDuty[📞 PagerDuty<br/>On-call escalation]
        end
    end

    App --> ReqMetrics
    App --> AuthMetrics
    App --> APIMetrics
    App --> PerfMetrics
    
    App --> Logger
    Logger --> AccessLogs
    Logger --> ErrorLogs
    Logger --> SecurityLogs
    Logger --> AuditLogs
    Logger --> FileRotation
    
    FileRotation --> LogAggregation
    ReqMetrics --> Dashboard
    AuthMetrics --> Dashboard
    APIMetrics --> Dashboard
    PerfMetrics --> Dashboard
    
    Dashboard --> Alerts
    LogAggregation --> Alerts
    
    Alerts --> Email
    Alerts --> Slack
    Alerts --> PagerDuty

    classDef app fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef metrics fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef logs fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef analysis fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef alerts fill:#ffebee,stroke:#d32f2f,stroke-width:2px

    class App app
    class ReqMetrics,AuthMetrics,APIMetrics,PerfMetrics metrics
    class Logger,AccessLogs,ErrorLogs,SecurityLogs,AuditLogs,FileRotation logs
    class LogAggregation,Dashboard,Alerts analysis
    class Email,Slack,PagerDuty alerts
```

### Application Metrics
- Request count and response times
- Error rates by endpoint
- GitHub API usage and rate limits
- Authentication success/failure rates

### Infrastructure Metrics  
- CPU and memory utilization
- SSL certificate expiration monitoring
- Log file size and rotation health
- Process uptime and restart frequency

### Security Monitoring
- Failed authentication attempts
- Rate limit violations
- Suspicious request patterns
- SSL/TLS handshake failures

## 🔄 Maintenance & Updates

### Regular Maintenance Tasks
- **Weekly**: Review security logs for anomalies
- **Monthly**: Update Node.js dependencies (`npm audit` and `npm update`)
- **Quarterly**: SSL certificate renewal and validation
- **Annually**: Security audit and penetration testing

### Update Strategy
- Dependency updates tested in staging environment
- Gradual rollout with health check validation
- Rollback procedures documented and tested
- Security updates prioritized and expedited

## 📚 Related Documentation

### Lambda Microservices Deployment
- **[lambda/README.md](../lambda/README.md)** - Lambda function details and deployment
- **[LAMBDA_DEPLOYMENT.md](../LAMBDA_DEPLOYMENT.md)** - Step-by-step Lambda deployment
- **[SERVERLESS_QUICKSTART.md](../SERVERLESS_QUICKSTART.md)** - Quick start guide for serverless
- **[SERVERLESS_DEPLOYMENT.md](../SERVERLESS_DEPLOYMENT.md)** - Serverless architecture details
- **[template.yaml](../template.yaml)** - AWS SAM template for Lambda deployment
- **[samconfig.toml](../samconfig.toml)** - SAM CLI configuration

### EC2 Traditional Deployment
- **[AWS Deployment Checklist](../AWS_DEPLOYMENT_CHECKLIST.md)** - EC2 deployment guide
- **[AWS Quick Reference](../AWS_QUICK_REFERENCE.md)** - AWS resource reference
- **[AWS Implementation Summary](../AWS_IMPLEMENTATION_SUMMARY.md)** - Implementation details
- **[cloudformation/complete-stack.yaml](../cloudformation/complete-stack.yaml)** - Full EC2 stack template
- **[ec2-scripts/](../ec2-scripts/)** - EC2 deployment automation scripts

### General Documentation
- **[☁️ AWS Architecture](./aws/AWS_ARCHITECTURE.md)** - Comprehensive AWS deployment architecture
- **[README.md](../README.md)** - Project overview and quick start
- **[SETUP.md](../SETUP.md)** - Detailed setup instructions  
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Production deployment guide
- **[SECURITY.md](./SECURITY.md)** - Security best practices and modernization
- **[MODULE_UPDATES.md](../MODULE_UPDATES.md)** - Modernization changelog
- **[SECURITY_MODERNIZATION.md](../SECURITY_MODERNIZATION.md)** - Security upgrade details

---

*This architecture document represents Git-Captain v2.0 following the comprehensive modernization and security improvements completed in 2024, with AWS Lambda microservices deployment added December 2025.*
