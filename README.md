# Git-Captain 🚢

<div align="center">
  <img src="public/images/titaniccaptainMedium.png" alt="Git-Captain Logo" width="400"/>
  
  **Modern, secure Node.js application for managing GitHub repositories at scale**
  
  [![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](#security-features)
</div>

---

## 🌟 Overview

Git-Captain is a powerful web application that simplifies managing multiple GitHub repositories simultaneously. Originally created to solve the pain of creating same-named branches across numerous repositories for GitFlow and TeamCity workflows, it has evolved into a comprehensive repository management tool.

**Perfect for teams working with microservices, multi-repo projects, or any scenario requiring coordinated repository operations.**

---

## ✨ Features

- 🌿 **Branch Management**: Create, search, and delete branches across multiple repositories
- 🔍 **Pull Request Discovery**: Find open pull requests by base branch
- 🔐 **Secure GitHub OAuth**: Seamless authentication with GitHub
- 🛡️ **Enterprise Security**: Rate limiting, CORS, input validation, security headers
- 📊 **Real-time Results**: Live feedback with detailed operation logs
- 🎯 **Batch Operations**: Select multiple repositories for simultaneous operations
- 📱 **Modern UI**: Clean, responsive interface with loading states

---

## 🚀 Quick Start

### Deployment Options

Git-Captain can be deployed in multiple ways to suit your needs:

- **☁️ AWS Cloud**: Automated infrastructure deployment with Terraform and CloudFormation → [AWS Deployment Guide](docs/aws/AWS_ARCHITECTURE.md)
- **💻 On-Premises**: Traditional server installation → See [Local Installation](#local-installation) below
- **🐳 Docker**: Containerized deployment (coming soon)

### Local Installation

#### Prerequisites
- **Node.js 18+** 
- **GitHub account** with repository access
- **SSL certificates** (for HTTPS)

#### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ConfusedDeer/Git-Captain.git
   cd Git-Captain
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment** (see [Configuration](#configuration))

4. **Generate SSL certificates** (see [SSL Setup](#ssl-setup))

5. **Start the server**
   ```bash
   npm start
   ```

6. **Access the application**
   ```
   https://localhost:3000
   ```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the `controllers` directory:

```env
# GitHub OAuth Configuration
client_id=your_github_client_id
client_secret=your_github_client_secret
GITHUB_ORG_NAME=your_organization_name

# Server Configuration
PORT=3000
GIT_PORT_ENDPOINT=https://your-domain.com

# SSL Certificate Paths
privateKeyPath=./theKey.key
certificatePath=./theCert.cert
```

### GitHub OAuth Setup

1. **Create OAuth App** in GitHub:
   - Go to GitHub Settings → Developer settings → OAuth Apps
   - Click "New OAuth App"
   - **Application name**: Git-Captain
   - **Homepage URL**: `https://your-domain.com`
   - **Authorization callback URL**: `https://your-domain.com/authenticated.html`

2. **Copy credentials** to your `.env` file

### SSL Setup

**Generate self-signed certificates** (for development):

```bash
# Install OpenSSL
# Windows: Download from https://slproweb.com/products/Win32OpenSSL.html
# Linux: sudo apt install openssl

# Generate certificates
openssl req -nodes -new -x509 -keyout controllers/theKey.key -out controllers/theCert.cert

# Set proper permissions (Linux/Mac)
chmod 600 controllers/theKey.key controllers/theCert.cert
```

**For production**, use Let's Encrypt or purchase a CA-signed certificate.

---

## 🔒 Security Features

Git-Captain implements enterprise-grade security measures:

- **🛡️ Security Headers**: Helmet.js with CSP, HSTS, and security headers
- **🚦 Rate Limiting**: 
  - General: 200 requests/minute
  - Auth operations: 300 requests/5 minutes
  - Sensitive operations: 25 requests/5 minutes
- **🌐 CORS Protection**: Configurable cross-origin policies
- **✅ Input Validation**: express-validator for all API endpoints
- **📝 Security Logging**: Comprehensive audit trails
- **🔐 Session Management**: Secure session handling with timeouts

---

## 📚 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gitCaptain/getToken` | GET/POST | OAuth token exchange |
| `/gitCaptain/searchForRepos` | POST | Search for all your organizations' repositories |
| `/gitCaptain/createBranches` | POST | Create a branch with the same name across all your repositories. Example: creating 'feature/newAwesomeBranch' will create this branch in all repos. |
| `/gitCaptain/searchForBranch` | POST | Searching for a specific branch across ALL your repos. Example: Searching for a branch named 'feature/newAwesomeBranch' will search for this branch and display in which repos that branch exists|
| `/gitCaptain/searchForPR` | POST | Find pull requests |
| `/gitCaptain/deleteBranches` | DELETE | Delete a branch with the same name across all your repositories. Example: deleting 'feature/newAwesomeBranch' will remove this branch from all repos where it exists. |
| `/gitCaptain/checkGitHubStatus` | GET | GitHub API status |

---

## 🏗️ Architecture Overview

Git-Captain v2.0 features a modern, secure architecture deployed on AWS infrastructure.

**[📊 View Architecture Diagram](docs/ARCHITECTURE.md#-high-level-architecture)**

**Key Components:**
- **AWS Infrastructure**: VPC with public/private subnets, EC2, RDS PostgreSQL, Lambda, CloudWatch
- **Security-First Design**: Multiple layers including AWS Security Groups, rate limiting, input validation, and security headers
- **OAuth Integration**: Seamless GitHub authentication with secure token handling
- **Modern HTTP Client**: Axios-based client replacing deprecated request library
- **Comprehensive Logging**: Winston-powered structured logging with CloudWatch integration
- **Production Ready**: PM2 process management with auto-restart and monitoring

📋 **Detailed Documentation:**
- **[AWS Deployment Architecture](docs/aws/AWS_ARCHITECTURE.md)** - Complete AWS cloud infrastructure guide
- **[System Architecture](docs/ARCHITECTURE.md)** - Complete architecture with interactive Mermaid diagrams
- **[Architecture Tools](docs/ARCHITECTURE_TOOLS.md)** - Guide to various diagramming tools for GitHub
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Security Overview](docs/SECURITY.md)** - Security features and best practices

---

## 🛠️ Development

### NPM Scripts
```bash
npm start          # Start production server
npm run dev        # Start development server (if configured)
npm test           # Run tests
npm run lint       # Code linting
npm audit          # Security audit
```

### Project Structure
```
Git-Captain/
├── controllers/           # Backend logic
│   ├── server.js         # Main server file (+/health endpoint)
│   ├── config.js         # Configuration management
│   ├── middleware.js     # Security middleware
│   ├── validation.js     # Input validation schemas
│   ├── httpClient.js     # HTTP client (Axios wrapper)
│   ├── logger.js         # Winston logging setup
│   └── .env             # Environment variables
├── public/               # Frontend assets
│   ├── js/              # JavaScript files
│   ├── css/             # Stylesheets
│   ├── images/          # Images and icons
│   └── views/           # HTML templates
├── docs/                # Documentation
│   └── aws/             # AWS deployment documentation
│       ├── ARCHITECTURE.md      # AWS architecture + Mermaid diagram
│       └── DEPLOYMENT_GUIDE.md  # Step-by-step AWS deployment
├── terraform/           # Infrastructure as Code (Networking)
│   ├── main.tf          # VPC orchestration
│   ├── modules/         # Reusable Terraform modules
│   │   ├── vpc/         # VPC, subnets, IGW, route tables
│   │   ├── security-groups/  # ALB, EC2, RDS, Lambda SGs
│   │   └── nat-gateway/ # NAT Gateway + EIP
│   └── outputs.tf       # Export to AWS SSM Parameter Store
├── cloudformation/      # Infrastructure as Code (Application Layer)
│   ├── ec2-alb-autoscaling.yaml  # EC2, ALB, ASG, Launch Template
│   ├── rds.yaml                  # PostgreSQL RDS + Secrets Manager
│   ├── lambda-s3-logging.yaml    # Lambda S3 upload logger (Python)
│   ├── cloudwatch-monitoring.yaml # Alarms, Dashboard, SNS
│   └── waf.yaml                  # AWS WAF + rate limiting
├── boto3-scripts/       # Python AWS automation
│   ├── setup_secrets.py      # Secrets Manager setup
│   ├── s3_manager.py         # S3 bucket operations
│   ├── ec2_operations.py     # EC2/ASG management CLI
│   ├── lambda_test.py        # Lambda testing utilities
│   ├── requirements.txt      # Python dependencies
│   └── README.md            # Boto3 scripts documentation
├── ec2-scripts/         # EC2 bootstrap and deployment
│   ├── user-data.sh     # EC2 initialization script
│   ├── app-update.sh    # Application deployment script
│   └── health-check.sh  # Health check script
├── .github/             # CI/CD automation
│   └── workflows/       # GitHub Actions workflows
│       ├── deploy-infrastructure.yml  # Terraform + CloudFormation
│       ├── deploy-application.yml     # App updates + ASG refresh
│       └── test.yml                   # Linting, audits, IaC validation
├── logs/                # Application logs
└── scripts/             # Utility scripts
```

---

## 🚢 Deployment

### Development (Local)
```bash
npm install
# Configure .env file
npm start
```

### Production Options

#### Option 1: AWS Cloud Deployment (Recommended) ☁️

**Complete Infrastructure as Code deployment** with Terraform and CloudFormation:

```bash
# Quick Deploy (Prerequisites: AWS CLI, Terraform, Python 3.9+)
cd terraform && terraform init && terraform apply
aws cloudformation deploy --template-file cloudformation/rds.yaml --stack-name git-captain-rds
# ... continue with remaining stacks (see full guide below)
```

**AWS Infrastructure Features:**
- ✅ **VPC with Multi-AZ**: 2 public + 2 private subnets across 2 availability zones
- ✅ **Auto Scaling**: EC2 instances (t3.micro, 2-6 capacity) with Application Load Balancer
- ✅ **RDS PostgreSQL**: db.t3.micro with automated backups and encryption
- ✅ **S3 Buckets**: Static assets, application logs, SSL certificates
- ✅ **AWS Lambda**: S3 upload logger (Python 3.11)
- ✅ **CloudWatch**: Monitoring, alarms, and centralized logging
- ✅ **AWS WAF**: Rate limiting (2000 req/5min) + managed rules
- ✅ **Secrets Manager**: Secure environment variable storage
- ✅ **CI/CD Pipeline**: GitHub Actions with OIDC authentication

**Monthly Cost**: ~$93/month (t3.micro instances, db.t3.micro RDS, minimal data transfer)

📋 **Complete AWS Documentation:**
- **[AWS Architecture](docs/aws/ARCHITECTURE.md)** - Architecture diagram, component specs, cost analysis
- **[AWS Deployment Guide](docs/aws/DEPLOYMENT_GUIDE.md)** - Step-by-step deployment (Console, CLI, Boto3)
- **[Boto3 Scripts](boto3-scripts/README.md)** - Python automation tools for AWS operations

**Quick AWS Setup:**
```bash
# 1. Store secrets in AWS Secrets Manager
cd boto3-scripts
python3 setup_secrets.py

# 2. Deploy VPC networking with Terraform
cd ../terraform
terraform init
terraform plan
terraform apply

# 3. Deploy application infrastructure with CloudFormation
cd ../cloudformation
aws cloudformation create-stack --stack-name git-captain-rds \
  --template-body file://rds.yaml --capabilities CAPABILITY_IAM

aws cloudformation create-stack --stack-name git-captain-ec2-alb \
  --template-body file://ec2-alb-autoscaling.yaml --capabilities CAPABILITY_IAM

# 4. Configure GitHub OAuth with ALB DNS name
# 5. Access application via ALB DNS: http://git-captain-prod-alb-XXXX.us-east-2.elb.amazonaws.com
```

**Deployment Modes:**
- **AWS Console**: Manual deployment via web interface (beginner-friendly)
- **AWS CLI**: Command-line deployment with CloudFormation/Terraform (recommended)
- **Boto3 Scripts**: Python automation for S3, EC2, Lambda, Secrets Manager operations
- **GitHub Actions**: Automated CI/CD pipeline triggered by git push

---

#### Option 2: Reverse Proxy (Traditional)
Use nginx or Apache to handle SSL and forward to port 3000:

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass https://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Option 3: Other Cloud Platforms
- **Azure**: App Service or Container Instances  
- **Google Cloud**: Cloud Run or Compute Engine
- **Heroku**: Direct deployment with buildpacks

### Firewall Configuration

**Basic firewall setup** for production:

```bash
# Linux (UFW)
sudo ufw allow 3000
sudo ufw allow 443

# Windows
netsh advfirewall firewall add rule name="Git-Captain" dir=in action=allow protocol=TCP localport=3000
```

**For detailed enterprise deployment**, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## 📋 Recent Updates (v2.0)

### ☁️ **AWS Cloud Infrastructure (November 2025)**
- ✅ **Complete AWS deployment solution** with Terraform + CloudFormation
- ✅ **VPC networking with Multi-AZ architecture** (2 public + 2 private subnets)
- ✅ **Auto Scaling EC2 instances** (2-6 t3.micro) behind Application Load Balancer
- ✅ **RDS PostgreSQL database** (db.t3.micro) with automated backups + encryption
- ✅ **S3 buckets** for static assets, logs, SSL certificates with lifecycle policies
- ✅ **AWS Lambda S3 upload logger** (Python 3.11) with CloudWatch logging
- ✅ **CloudWatch monitoring** with 7 alarms + custom dashboard
- ✅ **AWS WAF** with rate limiting (2000 req/5min) + AWS managed rules
- ✅ **AWS Secrets Manager** integration for secure credential storage
- ✅ **GitHub Actions CI/CD** with OIDC authentication (no access keys)
- ✅ **Boto3 automation scripts** (4 Python tools for AWS operations)
- ✅ **Comprehensive AWS documentation** (architecture diagram + deployment guide)
- ✅ **Health endpoint** (`/health`) for ALB health checks and monitoring

### 🔄 **Modernization (July 2025)**
- ✅ **Removed deprecated `request` library** → Modern Axios HTTP client
- ✅ **Added comprehensive security middleware** (Helmet, CORS, Rate limiting)
- ✅ **Implemented input validation** for all API endpoints
- ✅ **Modern async/await patterns** throughout codebase
- ✅ **Environment-based configuration** (.env files)
- ✅ **Structured logging system** with Winston
- ✅ **Fixed API response formatting** for consistent client-server communication
- ✅ **Updated all dependencies** to latest secure versions
- ✅ **Eliminated security vulnerabilities** (npm audit clean)

### 🐛 **Bug Fixes**
- ✅ **Branch search results now display correctly** in UI
- ✅ **Pull request search functionality restored**
- ✅ **OAuth flow improvements** with proper error handling
- ✅ **Rate limiting optimized** for development and production
- ✅ **GitHub API URL corrections** for branch operations

### 📖 **Documentation**
- ✅ **Complete README overhaul** (this document)
- ✅ **Enterprise deployment guide** (docs/DEPLOYMENT.md)
- ✅ **Technical change documentation** (MODULE_UPDATES.md)
- ✅ **Architecture documentation with rich diagrams** (docs/ARCHITECTURE.md)
- ✅ **Mermaid diagram collection** (docs/ARCHITECTURE_MERMAID.md)

#### 📊 **Visual Architecture**
All documentation now includes rich Mermaid diagrams that render beautifully in both VS Code and GitHub:
- 🏗️ **System Architecture**: High-level component overview
- 🔄 **Request Flow**: OAuth and API call sequences  
- ⚡ **Error Handling**: Comprehensive error management flows
- 🛡️ **Security Stack**: Middleware and protection layers
- 🔧 **Technology Stack**: Complete dependency mapping

---

## 🧪 Testing

### Manual Testing
1. **OAuth Flow**: Login → Token exchange → Repository access
2. **Branch Operations**: Create, search, delete across multiple repos
3. **Pull Request Search**: Find PRs by base branch
4. **Error Handling**: Test rate limits, invalid inputs, network errors

### Automated Testing
```bash
npm test  # Run test suite (when implemented)
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make changes** following our coding standards
4. **Test thoroughly** 
5. **Submit a pull request**

### Development Guidelines
- Follow existing code style and patterns
- Add comments for complex logic
- Update documentation for new features
- Ensure security best practices
- Test across different environments

---

## 📊 Monitoring & Troubleshooting

### Health Checks
```bash
# Check application status
curl -k https://localhost:3000/health

# View logs
tail -f logs/git-captain-$(date +%Y-%m-%d).log
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Port 3000 in use | `lsof -i :3000` and kill process |
| SSL certificate errors | Regenerate certificates or check paths |
| Rate limit 429 errors | Wait or increase limits in middleware.js |
| OAuth callback issues | Verify GitHub OAuth app callback URL |

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🏆 Built With

### Application Stack
- [Node.js](https://nodejs.org/) — JavaScript runtime
- [Express.js](https://expressjs.com/) — Web framework
- [GitHub API](https://docs.github.com/en/rest) — Repository integration
- [Axios](https://axios-http.com/) — HTTP client
- [Helmet.js](https://helmetjs.github.io/) — Security middleware
- [Winston](https://github.com/winstonjs/winston) — Logging framework

### AWS Infrastructure
- [AWS VPC](https://aws.amazon.com/vpc/) — Network isolation with Multi-AZ architecture
- [AWS EC2](https://aws.amazon.com/ec2/) — Auto Scaling compute instances (t3.micro)
- [Application Load Balancer](https://aws.amazon.com/elasticloadbalancing/) — Traffic distribution + SSL termination
- [Amazon RDS](https://aws.amazon.com/rds/) — PostgreSQL database (db.t3.micro)
- [Amazon S3](https://aws.amazon.com/s3/) — Object storage for assets, logs, SSL certs
- [AWS Lambda](https://aws.amazon.com/lambda/) — Serverless S3 upload logging (Python 3.11)
- [Amazon CloudWatch](https://aws.amazon.com/cloudwatch/) — Monitoring, logs, alarms, dashboards
- [AWS WAF](https://aws.amazon.com/waf/) — Web application firewall with rate limiting
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) — Secure credential storage
- [Terraform](https://www.terraform.io/) — Infrastructure as Code (networking layer)
- [AWS CloudFormation](https://aws.amazon.com/cloudformation/) — Infrastructure as Code (application layer)
- [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK for Python automation
- [GitHub Actions](https://github.com/features/actions) — CI/CD pipeline with OIDC authentication

---

## 👥 Authors & Contributors

- **[ConfusedDeer](https://github.com/ConfusedDeer)** — Original creator and maintainer
- **[CrunchyFerrett](https://github.com/CrunchyFerrett)** — Early frontend development
- **Community Contributors** — Various improvements and bug fixes

---

## 🙏 Acknowledgments

- **[j4p4n](https://openclipart.org/detail/282062/titanic-captain)** — "Titanic Captain" image from [openclipart.org](https://openclipart.org) under [CC0 License](https://creativecommons.org/publicdomain/zero/1.0/)
- **[Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)** — OpenSSL Windows installer
- **GitHub Community** — For the robust API and OAuth system

---

## 🔮 Roadmap

### Upcoming Features
- [ ] **Multi-organization support**
- [ ] **Webhook integration** for automated workflows
- [ ] **Branch protection rule management**
- [ ] **Bulk repository creation**
- [ ] **Advanced filtering and search**
- [ ] **REST API for external integration**
- [ ] **Comprehensive test suite**
- [ ] **Database integration** for operation history (RDS PostgreSQL schema ready)

### Long-term Goals
- [ ] **Mobile-responsive PWA**
- [ ] **Real-time collaboration features**
- [ ] **Integration with CI/CD platforms** (TeamCity, Jenkins, CircleCI)
- [ ] **Advanced analytics and reporting**
- [ ] **AWS API Gateway + Step Functions** integration
- [ ] **Multi-region deployment** with Route 53 failover

### Recently Completed ✅
- [x] **AWS Cloud Deployment** - Complete IaC solution with Terraform + CloudFormation
- [x] **Auto Scaling Infrastructure** - EC2 Auto Scaling + Application Load Balancer
- [x] **Serverless Logging** - AWS Lambda S3 upload logger with CloudWatch
- [x] **Comprehensive Monitoring** - CloudWatch alarms, dashboard, SNS notifications
- [x] **CI/CD Pipeline** - GitHub Actions with automated infrastructure deployment
- [x] **Security Hardening** - AWS WAF, Secrets Manager, Security Groups

---

<div align="center">

**⭐ Star this repository if Git-Captain helps you manage your repositories more efficiently!**

[Report Bug](https://github.com/ConfusedDeer/Git-Captain/issues) · [Request Feature](https://github.com/ConfusedDeer/Git-Captain/issues) · [Documentation](docs/DEPLOYMENT.md)

</div>
