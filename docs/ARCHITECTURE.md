# Git-Captain v2.0 Architecture

## 🏗️ System Overview

Git-Captain is a modernized Node.js web application that provides a secure interface for GitHub repository management with OAuth authentication and comprehensive security middleware.

**🌐 AWS Deployment**: Git-Captain is deployed as a serverless application on AWS Lambda with Function URL. See [AWS Architecture Documentation](./aws/AWS_ARCHITECTURE.md) for detailed cloud deployment information.

## 📍 Deployment Options

- **☁️ AWS Lambda** (Current): Serverless monolithic deployment with Function URL
- **☁️ AWS Lambda Microservices** (Planned): Separate Lambda functions with API Gateway
- **🖥️ On-Premises**: Traditional server deployment with reverse proxy
- **🐳 Docker**: Container-based deployment (future enhancement)

## 📊 Current Architecture - Monolithic Lambda

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
                    CreateBr[POST /gitCaptain/createBranches<br/>Create Branches]
                    DeleteBr[DELETE /gitCaptain/deleteBranches<br/>Delete Branches]
                    SearchBr[POST /gitCaptain/searchForBranch<br/>Search Branch]
                    SearchPR[POST /gitCaptain/searchForPR<br/>Search Pull Request]
                    LogOff[POST /gitCaptain/logOff<br/>Revoke Token]
                end
            end
            
            Runtime[Node.js 18.x Runtime<br/>512MB Memory<br/>30s Timeout]
        end
        
        subgraph Services["<b>🛠️ AWS Services</b>"]
            CW[CloudWatch Logs<br/>Function Logs]
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
    DeleteBr --> GitHub
    SearchBr --> GitHub
    SearchPR --> GitHub
    LogOff --> OAuth
    
    Handler --> Runtime
    Runtime --> CW

    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style AWS fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style Lambda fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style Handler fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Routes fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Services fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style External fill:#f1f8e9,stroke:#689f38,stroke-width:3px
    
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

## 🔮 Future Architecture - Microservices with API Gateway

```mermaid
graph TB
    subgraph Client["<b>👤 Client Layer</b>"]
        User[🌐 Web Browser]
    end

    subgraph AWS["<b>☁️ AWS Infrastructure - us-east-2</b>"]
        subgraph Gateway["<b>🌐 API Gateway</b>"]
            API[REST API<br/>Single Entry Point<br/>CORS Enabled]
            
            subgraph Routes["<b>🛤️ Route Configuration</b>"]
                R1[GET / → web-server]
                R2[GET /authenticated.html → web-server]
                R3[GET /static/* → web-server]
                R4[POST /gitCaptain/getToken → auth-service]
                R5[POST /gitCaptain/searchForRepos → repo-service]
                R6[POST /gitCaptain/*Branches → branch-service]
                R7[POST /gitCaptain/searchForBranch → branch-service]
                R8[POST /gitCaptain/searchForPR → branch-service]
                R9[POST /gitCaptain/logOff → branch-service]
            end
        end
        
        subgraph Lambdas["<b>⚡ Lambda Microservices</b>"]
            WebLambda[🌐 web-server<br/>Static content & pages<br/>Client config injection<br/>Node.js 18.x]
            
            AuthLambda[🔐 auth-service<br/>OAuth token exchange<br/>GitHub authorization<br/>Node.js 18.x]
            
            RepoLambda[📦 repo-service<br/>Repository listing<br/>User & org repos<br/>Node.js 18.x]
            
            BranchLambda[🌿 branch-service<br/>Branch operations<br/>PR search & logout<br/>Node.js 18.x]
        end
        
        subgraph Services["<b>🛠️ AWS Services</b>"]
            CW[CloudWatch Logs<br/>Centralized Logging]
            Env[Environment Variables<br/>Per Function Config]
        end
    end

    subgraph External["<b>🌍 External Services</b>"]
        GitHub[GitHub API<br/>api.github.com]
        OAuth[GitHub OAuth<br/>github.com/login/oauth]
    end

    User -->|HTTPS| API
    API --> R1
    API --> R2
    API --> R3
    API --> R4
    API --> R5
    API --> R6
    API --> R7
    API --> R8
    API --> R9
    
    R1 --> WebLambda
    R2 --> WebLambda
    R3 --> WebLambda
    R4 --> AuthLambda
    R5 --> RepoLambda
    R6 --> BranchLambda
    R7 --> BranchLambda
    R8 --> BranchLambda
    R9 --> BranchLambda
    
    WebLambda --> Env
    AuthLambda --> OAuth
    AuthLambda --> Env
    RepoLambda --> GitHub
    RepoLambda --> Env
    BranchLambda --> GitHub
    BranchLambda --> OAuth
    BranchLambda --> Env
    
    WebLambda --> CW
    AuthLambda --> CW
    RepoLambda --> CW
    BranchLambda --> CW

    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style AWS fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style Gateway fill:#e8f5e9,stroke:#388e3c,stroke-width:3px
    style Routes fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Lambdas fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style Services fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style External fill:#f1f8e9,stroke:#689f38,stroke-width:3px
    
    style User fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style API fill:#43a047,stroke:#1b5e20,stroke-width:2px,color:#fff
    style WebLambda fill:#9c27b0,stroke:#4a148c,stroke-width:2px,color:#fff
    style AuthLambda fill:#fbc02d,stroke:#f57f17,stroke-width:2px,color:#000
    style RepoLambda fill:#1976d2,stroke:#0d47a1,stroke-width:2px,color:#fff
    style BranchLambda fill:#e91e63,stroke:#880e4f,stroke-width:2px,color:#fff
    style CW fill:#00acc1,stroke:#006064,stroke-width:2px,color:#fff
    style Env fill:#5e35b1,stroke:#311b92,stroke-width:2px,color:#fff
    style GitHub fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
    style OAuth fill:#7cb342,stroke:#33691e,stroke-width:2px,color:#fff
```

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

## 🔄 Request Flow Diagram

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
    style External fill:#f1f8e9,stroke:#689f38,stroke-width:3px
    
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
├── 📁 controllers/                    # Backend Core
│   ├── 🔧 server.js                  # Main application server
│   ├── 🌐 httpClient.js              # Axios-based HTTP client
│   ├── 🛡️ middleware.js              # Security middleware stack
│   ├── ✅ validation.js              # Input validation schemas
│   ├── 📝 logger.js                  # Winston logging configuration
│   ├── ⚙️ config.js                  # Environment & app configuration
│   └── 🔒 security.js                # Security utilities
├── 📁 public/                        # Frontend Assets
│   ├── 📁 css/                       # Stylesheets
│   │   └── 🎨 styles.css            # Main UI styling
│   ├── 📁 js/                        # Client-side JavaScript
│   │   ├── 🔧 tools.js               # API interaction utilities
│   │   ├── 🌿 branchUtils.js         # Branch operation helpers
│   │   └── ⚙️ viewUtils.js           # UI manipulation utilities
│   ├── 📁 images/                    # Static images & favicon
│   └── 📁 views/                     # HTML templates
│       ├── 📄 index.html             # Landing page
│       └── 🔐 authenticated.html     # OAuth callback page
├── 📁 docs/                          # Documentation
│   ├── 📋 ARCHITECTURE.md            # System architecture (this file)
│   ├── 🚀 DEPLOYMENT.md              # Deployment guide
│   └── 🔒 SECURITY.md                # Security documentation
├── 📁 logs/                          # Application logs
│   ├── 📄 git-captain-YYYY-MM-DD.log # Daily application logs
│   └── 🚨 git-captain-errors-YYYY-MM-DD.log # Error logs
├── 📁 test/                          # Test suites
│   └── 🧪 security.test.js           # Security tests
├── 📁 scripts/                       # Utility scripts
│   └── ⚙️ setup.js                   # Environment setup
├── 🔐 .env                           # Environment variables
├── 📦 package.json                   # Node.js dependencies
├── 📋 MODULE_UPDATES.md              # Modernization changelog
├── 📖 README.md                      # Project overview
└── ⚙️ SETUP.md                       # Setup instructions
```

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

- **[☁️ AWS Architecture](./aws/AWS_ARCHITECTURE.md)** - AWS cloud deployment architecture
- **[README.md](../README.md)** - Project overview and quick start
- **[SETUP.md](../SETUP.md)** - Detailed setup instructions  
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Production deployment guide
- **[SECURITY.md](./SECURITY.md)** - Security best practices
- **[MODULE_UPDATES.md](../MODULE_UPDATES.md)** - Modernization changelog
- **[AWS Deployment Checklist](../AWS_DEPLOYMENT_CHECKLIST.md)** - AWS deployment guide
- **[AWS Quick Reference](../AWS_QUICK_REFERENCE.md)** - AWS resource reference

---

*This architecture document represents Git-Captain v2.0 following the comprehensive modernization and security improvements completed in 2024, with AWS cloud deployment added December 2025.*
