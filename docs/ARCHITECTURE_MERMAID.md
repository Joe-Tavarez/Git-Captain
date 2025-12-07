# Git-Captain v2.0 Architecture Diagrams

## 🏗️ Current Architecture - Monolithic Lambda

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[🌐 Browser Client]
        UI[📱 User Interface]
    end
    
    subgraph "AWS Lambda - us-east-2"
        FunctionURL[🌐 Function URL<br/>Public HTTPS Endpoint<br/>git-captain]
        
        subgraph "Lambda Function Handler"
            Express[⚙️ Express.js App<br/>serverless-http wrapper<br/>Node.js 18.x]
            
            subgraph "All Routes in One Function"
                Health[📊 GET /health]
                Status[🔍 GET /gitCaptain/checkGitHubStatus]
                Home[🏠 GET /]
                AuthPage[🔐 GET /authenticated.html]
                Static[📁 GET /static/*]
                ConfigJS[⚙️ GET /config.js]
                Token[🔑 POST /gitCaptain/getToken]
                Repos[📦 POST /gitCaptain/searchForRepos]
                CreateBr[🌿 POST /gitCaptain/createBranches]
                DeleteBr[🗑️ DELETE /gitCaptain/deleteBranches]
                SearchBr[🔍 POST /gitCaptain/searchForBranch]
                SearchPR[📋 POST /gitCaptain/searchForPR]
                LogOff[🚪 POST /gitCaptain/logOff]
            end
            
            Config[📝 Environment Variables<br/>GITHUB_CLIENT_ID<br/>GITHUB_CLIENT_SECRET<br/>GITHUB_ORG_NAME<br/>NODE_ENV]
        end
        
        CloudWatch[📊 CloudWatch Logs]
    end
    
    subgraph "External Services"
        GitHub[🐙 GitHub API<br/>api.github.com]
        OAuth[🔑 GitHub OAuth<br/>github.com/login/oauth]
    end
    
    Browser --> UI
    UI --> FunctionURL
    FunctionURL --> Express
    
    Express --> Health
    Express --> Status
    Express --> Home
    Express --> AuthPage
    Express --> Static
    Express --> ConfigJS
    Express --> Token
    Express --> Repos
    Express --> CreateBr
    Express --> DeleteBr
    Express --> SearchBr
    Express --> SearchPR
    Express --> LogOff
    
    Home --> Config
    AuthPage --> Config
    ConfigJS --> Config
    Token --> OAuth
    Token --> Config
    Repos --> GitHub
    Repos --> Config
    CreateBr --> GitHub
    CreateBr --> Config
    DeleteBr --> GitHub
    DeleteBr --> Config
    SearchBr --> GitHub
    SearchBr --> Config
    SearchPR --> GitHub
    SearchPR --> Config
    LogOff --> OAuth
    LogOff --> Config
    
    Express --> CloudWatch
    
    classDef client fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef lambda fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef routes fill:#f3e5f5,stroke:#4a148c,stroke-width:1px
    classDef external fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef config fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    
    class Browser,UI client
    class FunctionURL,Express lambda
    class Health,Status,Home,AuthPage,Static,ConfigJS,Token,Repos,CreateBr,DeleteBr,SearchBr,SearchPR,LogOff routes
    class GitHub,OAuth external
    class Config,CloudWatch config
```

## 🔮 Future Architecture - Microservices with API Gateway

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[🌐 Browser Client]
        UI[📱 User Interface]
    end
    
    subgraph "AWS Infrastructure - us-east-2"
        API[🌐 API Gateway<br/>REST API<br/>Single Entry Point]
        
        subgraph "Lambda Microservices"
            WebLambda[🌐 web-server<br/>Static content & pages<br/>Client config injection<br/>Node.js 18.x]
            
            AuthLambda[🔐 auth-service<br/>OAuth token exchange<br/>GitHub authorization<br/>Node.js 18.x]
            
            RepoLambda[📦 repo-service<br/>Repository listing<br/>User & org repos<br/>Node.js 18.x]
            
            BranchLambda[🌿 branch-service<br/>Branch operations<br/>PR search & logout<br/>Node.js 18.x]
        end
        
        CloudWatch[📊 CloudWatch Logs<br/>Centralized]
        Env[📝 Environment Variables<br/>Per Function Config]
    end
    
    subgraph "Route Mapping"
        R1[GET / → web-server]
        R2[GET /authenticated.html → web-server]
        R3[GET /static/* → web-server]
        R4[POST /gitCaptain/getToken → auth-service]
        R5[POST /gitCaptain/searchForRepos → repo-service]
        R6[POST /gitCaptain/*Branches → branch-service]
        R7[POST /gitCaptain/searchFor* → branch-service]
        R8[POST /gitCaptain/logOff → branch-service]
    end
    
    subgraph "External Services"
        GitHub[🐙 GitHub API<br/>api.github.com]
        OAuth[🔑 GitHub OAuth<br/>github.com/login/oauth]
    end
    
    Browser --> UI
    UI --> API
    
    API --> R1
    API --> R2
    API --> R3
    API --> R4
    API --> R5
    API --> R6
    API --> R7
    API --> R8
    
    R1 --> WebLambda
    R2 --> WebLambda
    R3 --> WebLambda
    R4 --> AuthLambda
    R5 --> RepoLambda
    R6 --> BranchLambda
    R7 --> BranchLambda
    R8 --> BranchLambda
    
    WebLambda --> Env
    AuthLambda --> OAuth
    AuthLambda --> Env
    RepoLambda --> GitHub
    RepoLambda --> Env
    BranchLambda --> GitHub
    BranchLambda --> OAuth
    BranchLambda --> Env
    
    WebLambda --> CloudWatch
    AuthLambda --> CloudWatch
    RepoLambda --> CloudWatch
    BranchLambda --> CloudWatch
    
    classDef client fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef gateway fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef lambda fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef routes fill:#f3e5f5,stroke:#4a148c,stroke-width:1px
    classDef external fill:#ffebee,stroke:#b71c1c,stroke-width:2px
    classDef config fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    
    class Browser,UI client
    class API gateway
    class WebLambda,AuthLambda,RepoLambda,BranchLambda lambda
    class R1,R2,R3,R4,R5,R6,R7,R8 routes
    class GitHub,OAuth external
    class CloudWatch,Env config
```

## 🔄 Request Flow Architecture

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant B as 🌐 Browser
    participant IGW as 🌐 Internet Gateway
    participant SG as 🛡️ Security Groups
    participant EC2 as 🖥️ EC2 Instance
    participant S as 🛡️ Security Layer
    participant A as ⚙️ Application
    participant NAT as 🔄 NAT Gateway
    participant G as 🐙 GitHub API
    participant CW as 📊 CloudWatch
    
    U->>B: Click "Search Branches"
    B->>IGW: HTTPS Request (Port 3000)
    IGW->>SG: Route to VPC
    SG->>EC2: Allow Port 3000
    EC2->>S: PM2 → Node.js App
    S->>S: Rate Limiting Check
    S->>S: CORS Validation
    S->>S: Security Headers
    S->>S: Input Validation
    S->>A: Validated Request
    A->>A: Route to Handler
    A->>NAT: Forward Request
    NAT->>G: GitHub API Call
    G-->>NAT: API Response
    NAT-->>A: Return Data
    A->>A: Format Response
    A->>CW: Log Operation
    A-->>S: JSON Response
    S-->>EC2: Send Response
    EC2-->>B: Secure Response
    B->>B: Update UI
    B-->>U: Display Results
```

## 🔒 Security Layer Architecture

```mermaid
graph TD
    Internet[🌍 Internet Traffic] --> Layer1
    
    subgraph "Security Layers"
        Layer1[🔒 Layer 1: Network Security<br/>• HTTPS/TLS<br/>• SSL Certificates<br/>• Port Restrictions]
        Layer2[🚦 Layer 2: Rate Limiting<br/>• 200 req/min General<br/>• 300 req/5min Auth<br/>• 25 req/5min Sensitive]
        Layer3[🌐 Layer 3: CORS Protection<br/>• Origin Validation<br/>• Method Restrictions<br/>• Credential Handling]
        Layer4[🛡️ Layer 4: Security Headers<br/>• Content Security Policy<br/>• X-Frame-Options<br/>• HSTS]
        Layer5[✅ Layer 5: Input Validation<br/>• Schema Validation<br/>• Input Sanitization<br/>• Type Checking]
        Layer6[🔐 Layer 6: Application Logic<br/>• OAuth Validation<br/>• Session Management<br/>• Audit Logging]
    end
    
    Application[⚙️ Application Core]
    
    Layer1 --> Layer2
    Layer2 --> Layer3
    Layer3 --> Layer4
    Layer4 --> Layer5
    Layer5 --> Layer6
    Layer6 --> Application
    
    classDef security fill:#ffebee
    class Layer1,Layer2,Layer3,Layer4,Layer5,Layer6 security
```

## 🌐 OAuth 2.0 Flow

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant B as 🌐 Browser
    participant A as ⚙️ Git-Captain
    participant G as 🐙 GitHub OAuth
    participant API as 📡 GitHub API
    
    U->>B: Click "Login with GitHub"
    B->>G: Redirect to GitHub OAuth
    G->>U: Show Authorization Page
    U->>G: Grant Permission
    G->>B: Redirect with code
    Note over B: /authenticated.html?code=xyz123
    B->>A: POST /getToken with code
    A->>G: Exchange code for token
    G-->>A: Return access_token
    A-->>B: Return token to client
    B->>B: Store token in memory
    
    loop API Operations
        B->>A: API Request + token
        A->>API: GitHub API Call + token
        API-->>A: API Response
        A-->>B: Formatted Response
        B->>B: Update UI
    end
```

## 🗂️ Component Architecture

```mermaid
graph TB
    subgraph "AWS Cloud - EC2 Instance"
        subgraph "Frontend (Browser)"
            HTML[📄 HTML Templates<br/>/opt/git-captain/public/views/]
            CSS[🎨 CSS Styles<br/>/opt/git-captain/public/css/]
            JS[📜 JavaScript Modules<br/>/opt/git-captain/public/js/]
            
            subgraph "JS Modules"
                Tools[🔧 tools.js<br/>• AJAX calls<br/>• Auth management]
                Branch[🌿 branchUtils.js<br/>• Branch operations<br/>• Repository management]
                View[👁️ viewUtils.js<br/>• UI updates<br/>• Result display]
            end
        end
        
        subgraph "Backend (Node.js)"
            Server[🖥️ server.js<br/>Main Application<br/>PM2 Managed]
            
            subgraph "Core Modules"
                HTTP[🌐 httpClient.js<br/>• Axios wrapper<br/>• GitHub API calls]
                Middleware[🛡️ middleware.js<br/>• Security stack<br/>• Rate limiting]
                Validation[✅ validation.js<br/>• Input schemas<br/>• Sanitization]
                Logger[📝 logger.js<br/>• Winston logging<br/>• File rotation]
                Config[⚙️ config.js<br/>• .env vars<br/>• App settings]
            end
            
            SSL[🔒 SSL Certificates<br/>theKey.key + theCert.cert]
        end
    end
    
    subgraph "AWS Services"
        RDS[(💾 RDS PostgreSQL<br/>Private Subnet<br/>Port 5432)]
        Lambda[⚡ Lambda Function<br/>S3 Logging<br/>Python 3.9]
        CloudWatch[📊 CloudWatch<br/>Logs & Metrics]
        S3[📦 S3 Bucket<br/>Log Storage]
    end
    
    subgraph "External APIs"
        GitHubAPI[🐙 GitHub API<br/>• Repository management<br/>• Branch operations<br/>• OAuth services]
    end
    
    HTML --> JS
    CSS --> JS
    JS --> Tools
    JS --> Branch
    JS --> View
    
    Tools --> Server
    Branch --> Server
    View --> Server
    
    Server --> HTTP
    Server --> Middleware
    Server --> Validation
    Server --> Logger
    Server --> Config
    Server --> SSL
    Server --> RDS
    
    Logger --> CloudWatch
    CloudWatch --> S3
    Lambda --> S3
    
    HTTP --> GitHubAPI
    
    classDef frontend fill:#e3f2fd
    classDef backend fill:#f3e5f5
    classDef external fill:#e8f5e8
    classDef aws fill:#ff9800
    
    class HTML,CSS,JS,Tools,Branch,View frontend
    class Server,HTTP,Middleware,Validation,Logger,Config,SSL backend
    class GitHubAPI external
    class RDS,Lambda,CloudWatch,S3 aws
```

## 📊 Data Flow Diagram

```mermaid
flowchart TD
    Start([👤 User Action]) --> Input{🔍 Input Type}
    
    Input -->|Branch Search| Search[🌿 Search Branch]
    Input -->|Branch Create| Create[➕ Create Branch]
    Input -->|Branch Delete| Delete[🗑️ Delete Branch]
    Input -->|PR Search| PRSearch[📋 Search PRs]
    
    Search --> Validate[✅ Validate Input]
    Create --> Validate
    Delete --> Validate
    PRSearch --> Validate
    
    Validate --> Auth[🔐 Check Authentication]
    Auth --> RateLimit[🚦 Rate Limit Check]
    RateLimit --> GitHubCall[📡 GitHub API Call]
    
    GitHubCall --> Success{✅ Success?}
    Success -->|Yes| Format[📝 Format Response]
    Success -->|No| Error[❌ Handle Error]
    
    Format --> Display[🖥️ Update UI]
    Error --> Display
    
    Display --> End([🏁 Complete])
    
    classDef action fill:#e8f5e8
    classDef process fill:#fff3e0
    classDef decision fill:#ffebee
    classDef endpoint fill:#e3f2fd
    
    class Start,End action
    class Validate,Auth,RateLimit,Format,Error process
    class Input,Success decision
    class Search,Create,Delete,PRSearch,GitHubCall,Display endpoint
```

## 💾 File System Structure

```mermaid
graph TD
    Root[📁 /opt/git-captain/<br/>EC2 Instance] --> Controllers[📁 controllers/]
    Root --> Public[📁 public/]
    Root --> Docs[📁 docs/]
    Root --> Logs[📁 logs/]
    Root --> Config[📄 Config Files]
    Root --> AWS[📁 AWS IaC]
    
    Controllers --> Server[🔧 server.js]
    Controllers --> HTTP[🌐 httpClient.js]
    Controllers --> Mid[🛡️ middleware.js]
    Controllers --> Val[✅ validation.js]
    Controllers --> Log[📝 logger.js]
    Controllers --> Cfg[⚙️ config.js]
    Controllers --> Env[🔐 .env]
    Controllers --> SSL[🔑 SSL Certificates<br/>theKey.key + theCert.cert]
    
    Public --> CSS[📁 css/]
    Public --> JS[📁 js/]
    Public --> Images[📁 images/]
    Public --> Views[📁 views/]
    
    JS --> Tools[🔧 tools.js]
    JS --> Branch[🌿 branchUtils.js]
    JS --> ViewUtils[👁️ viewUtils.js]
    
    Views --> Index[🏠 index.html]
    Views --> Auth[🔐 authenticated.html]
    
    Docs --> Deploy[📖 DEPLOYMENT.md]
    Docs --> Arch[🏗️ ARCHITECTURE.md]
    Docs --> AWSDoc[☁️ aws/<br/>AWS_ARCHITECTURE.md]
    
    AWS --> Terraform[📦 terraform/<br/>VPC Infrastructure]
    AWS --> CloudFormation[☁️ cloudformation/<br/>EC2, RDS, Lambda]
    
    Config --> Package[📦 package.json]
    Config --> README[📖 README.md]
    Config --> Setup[⚡ SETUP.md]
    Config --> Updates[📋 MODULE_UPDATES.md]
    
    Logs --> AppLogs[📝 application.log<br/>error.log]
    Logs --> PM2Logs[🔄 PM2 Logs<br/>~/.pm2/logs/]
    Logs --> CloudWatchLogs[📊 CloudWatch Logs<br/>/aws/ec2/git-captain]
    
    classDef folder fill:#fff3e0
    classDef backend fill:#f3e5f5
    classDef frontend fill:#e3f2fd
    classDef docs fill:#e8f5e8
    classDef config fill:#ffebee
    classDef aws fill:#ff9800
    
    class Root,Controllers,Public,Docs,Logs folder
    class Server,HTTP,Mid,Val,Log,Cfg,Env,SSL backend
    class CSS,JS,Images,Views,Tools,Branch,ViewUtils,Index,Auth frontend
    class Deploy,Arch,AWSDoc docs
    class Config,Package,README,Setup,Updates config
    class AWS,Terraform,CloudFormation,AppLogs,PM2Logs,CloudWatchLogs aws
```

---

## 🎯 Why Mermaid is Perfect for GitHub:

✅ **Native GitHub Support** - Renders automatically in README.md
✅ **Version Control Friendly** - Text-based, easy to diff
✅ **Professional Looking** - Clean, modern diagrams
✅ **Interactive** - Clickable elements (in some contexts)
✅ **Responsive** - Scales well on mobile
✅ **Easy to Maintain** - Update diagrams with simple text changes

You can copy any of these Mermaid diagrams directly into your README.md or documentation files, and they'll render beautifully on GitHub! 🚢
