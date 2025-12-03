# Git-Captain v2.0 Architecture Diagrams

## 🏗️ High-Level System Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[🌐 Browser Client]
        UI[📱 User Interface]
    end
    
    subgraph "AWS Cloud Infrastructure"
        subgraph "VPC 10.0.0.0/16 - us-east-2"
            IGW[🌐 Internet Gateway]
            
            subgraph "Public Subnets"
                EC2[🖥️ EC2 Instance<br/>Amazon Linux 2023<br/>t3.micro]
                NAT[🔄 NAT Gateway]
            end
            
            subgraph "Private Subnets"
                RDS[(💾 RDS PostgreSQL 15<br/>db.t3.micro)]
                Lambda[⚡ Lambda S3 Logger<br/>Python 3.9]
            end
            
            SG[🛡️ Security Groups<br/>Web, DB, Lambda]
        end
        
        CloudWatch[📊 CloudWatch<br/>Logs & Metrics]
        S3[📦 S3 Bucket<br/>Log Storage]
        SSM[🔧 Systems Manager]
    end
    
    subgraph "Application Layer - EC2"
        App[⚙️ Node.js Application<br/>Port 3000<br/>PM2 Managed]
        
        subgraph "Security Middleware"
            Rate[🚦 Rate Limiter<br/>200/min, 300/5min]
            CORS[🌐 CORS Protection]
            Helmet[🛡️ Security Headers]
            Validation[✅ Input Validation]
        end
        
        subgraph "Core Components"
            Router[🔀 Express Router]
            Auth[🔐 OAuth Handler]
            Branch[🌿 Branch Manager]
            PR[📋 PR Manager]
            Static[📁 Static Files]
        end
        
        subgraph "Infrastructure"
            HTTP[🌐 HTTP Client<br/>Axios]
            Logger[📝 Winston Logger]
            Config[⚙️ Configuration<br/>.env]
            Middleware[🔧 Middleware Stack]
        end
    end
    
    subgraph "External Services"
        GitHub[🐙 GitHub API]
        OAuth[🔑 GitHub OAuth]
    end
    
    Browser --> IGW
    IGW --> SG
    SG --> EC2
    EC2 --> App
    App --> Rate
    Rate --> CORS
    CORS --> Helmet
    Helmet --> Validation
    Validation --> Router
    Router --> Auth
    Router --> Branch
    Router --> PR
    Router --> Static
    Auth --> HTTP
    Branch --> HTTP
    PR --> HTTP
    HTTP --> NAT
    NAT --> GitHub
    NAT --> OAuth
    App --> RDS
    Logger --> CloudWatch
    CloudWatch --> S3
    Lambda --> S3
    EC2 --> SSM
    
    classDef client fill:#e1f5fe
    classDef security fill:#fff3e0
    classDef core fill:#f3e5f5
    classDef external fill:#e8f5e8
    classDef aws fill:#ff9800
    
    class Browser,UI client
    class Rate,CORS,Helmet,Validation security
    class Router,Auth,Branch,PR,Static,HTTP,Logger,Config,Middleware core
    class GitHub,OAuth external
    class EC2,RDS,Lambda,CloudWatch,S3,NAT,IGW,SG,SSM aws
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
