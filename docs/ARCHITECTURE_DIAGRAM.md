# Git-Captain AWS Architecture - Academic Project

```mermaid
graph TB
    subgraph "AWS Cloud"
        subgraph "VPC (10.0.0.0/16)"
            subgraph "Public Subnet 1 (10.0.1.0/24) - us-east-2a"
                IGW[Internet Gateway]
                NAT1[NAT Gateway]
                ALB[Application Load Balancer]
                Bastion1[Bastion Host]
            end
            
            subgraph "Public Subnet 2 (10.0.2.0/24) - us-east-2b"
                NAT2[NAT Gateway]
                Bastion2[Bastion Host]
            end
            
            subgraph "Private Subnet 1 (10.0.10.0/24) - us-east-2a"
                EC2_1[EC2 Instance 1<br/>Git-Captain App]
                Lambda1[Lambda Function<br/>S3 Logger]
            end
            
            subgraph "Private Subnet 2 (10.0.11.0/24) - us-east-2b"
                EC2_2[EC2 Instance 2<br/>Git-Captain App]
                Lambda2[Lambda Function<br/>Git Operations]
            end
            
            subgraph "Private Subnet 3 (10.0.20.0/24) - us-east-2a"
                RDS_Primary[(RDS PostgreSQL<br/>Primary)]
            end
            
            subgraph "Private Subnet 4 (10.0.21.0/24) - us-east-2b"
                RDS_Standby[(RDS PostgreSQL<br/>Standby)]
            end
        end
        
        S3[S3 Bucket<br/>Static Assets + Logs]
        CloudWatch[CloudWatch Logs<br/>& Metrics]
        Secrets[Secrets Manager<br/>GitHub OAuth]
        ASG[Auto Scaling Group<br/>Min: 2, Max: 6]
        Route53[Route 53<br/>DNS]
        CloudFront[CloudFront CDN]
        APIGateway[API Gateway<br/>REST API]
        StepFunctions[Step Functions<br/>Workflow Orchestration]
    end
    
    subgraph "External"
        Users[Users/Browsers]
        GitHub[GitHub API]
        Developer[Developer<br/>CLI/Console/Boto3]
    end
    
    Users -->|HTTPS| CloudFront
    CloudFront -->|Static Content| S3
    CloudFront -->|API Requests| APIGateway
    APIGateway -->|Invoke| Lambda2
    APIGateway -->|HTTP| ALB
    
    ALB -->|Route| EC2_1
    ALB -->|Route| EC2_2
    ASG -->|Manages| EC2_1
    ASG -->|Manages| EC2_2
    
    EC2_1 -.->|Query/Store| RDS_Primary
    EC2_2 -.->|Query/Store| RDS_Primary
    RDS_Primary -.->|Replicate| RDS_Standby
    
    EC2_1 -.->|Read/Write| S3
    EC2_2 -.->|Read/Write| S3
    Lambda2 -.->|Read/Write| S3
    
    S3 -->|Event Trigger| Lambda1
    Lambda1 -->|Log| CloudWatch
    Lambda2 -->|Log| CloudWatch
    EC2_1 -->|Metrics/Logs| CloudWatch
    EC2_2 -->|Metrics/Logs| CloudWatch
    
    Lambda2 -.->|Get Secrets| Secrets
    EC2_1 -.->|Get Secrets| Secrets
    EC2_2 -.->|Get Secrets| Secrets
    
    Lambda2 <-->|API Calls| GitHub
    EC2_1 <-->|API Calls| GitHub
    EC2_2 <-->|API Calls| GitHub
    
    Developer -->|AWS CLI| EC2_1
    Developer -->|Boto3 Scripts| S3
    Developer -->|Console| CloudWatch
    
    StepFunctions -->|Orchestrate| Lambda1
    StepFunctions -->|Orchestrate| Lambda2
    
    IGW -.->|Route| ALB
    NAT1 -.->|Outbound| EC2_1
    NAT2 -.->|Outbound| EC2_2
    
    classDef public fill:#90EE90,stroke:#006400,stroke-width:2px
    classDef private fill:#FFB6C1,stroke:#8B0000,stroke-width:2px
    classDef storage fill:#87CEEB,stroke:#000080,stroke-width:2px
    classDef compute fill:#FFD700,stroke:#FF8C00,stroke-width:2px
    classDef security fill:#DDA0DD,stroke:#4B0082,stroke-width:2px
    
    class IGW,NAT1,NAT2,ALB,Bastion1,Bastion2 public
    class EC2_1,EC2_2,Lambda1,Lambda2,RDS_Primary,RDS_Standby private
    class S3,CloudWatch storage
    class ASG,CloudFront,APIGateway,StepFunctions compute
    class Secrets security
```

## Architecture Components

### Networking Layer (Terraform)
- **VPC**: 10.0.0.0/16 with DNS support
- **Public Subnets**: 2 subnets across AZs for high availability
  - Internet Gateway for public internet access
  - NAT Gateways for private subnet outbound traffic
  - Application Load Balancer
  - Bastion hosts for SSH access
- **Private Subnets**: 4 subnets for application and database tiers
  - EC2 instances (Git-Captain application)
  - Lambda functions
  - RDS database (Multi-AZ)

### Compute Layer (CloudFormation)
- **EC2 Instances**: Auto-scaled web servers (2-6 instances)
- **Application Load Balancer**: Traffic distribution
- **Auto Scaling Group**: Automatic scaling based on CPU/memory
- **Lambda Functions**: 
  - S3 upload logger (CloudWatch integration)
  - Git-Captain operations (GitHub API)

### Database Layer (CloudFormation)
- **RDS PostgreSQL**: Multi-AZ deployment
  - Primary in us-east-2a
  - Standby replica in us-east-2b
  - Automated backups (7-day retention)
  - Session storage and application data

### Storage Layer
- **S3 Bucket**: 
  - Static assets (HTML, CSS, JS)
  - Application logs
  - Backup files
  - Versioning enabled
  - Lifecycle policies

### Serverless Layer (CloudFormation)
- **Lambda Functions**: Event-driven compute
- **API Gateway**: RESTful API endpoints
- **Step Functions**: Workflow orchestration
- **CloudWatch**: Centralized logging and monitoring

### Security Layer
- **Security Groups**:
  - ALB: Allow 80/443 from internet
  - EC2: Allow 3000 from ALB only
  - RDS: Allow 5432 from EC2 only
  - Lambda: Allow HTTPS outbound
- **Secrets Manager**: GitHub OAuth credentials
- **IAM Roles**: Least privilege access

### CDN & DNS
- **CloudFront**: Global content delivery
- **Route 53**: DNS management (optional)

## AWS Services Used

✅ **Networking**: VPC, Subnets, Internet Gateway, NAT Gateway, Route Tables  
✅ **Compute**: EC2, Auto Scaling, Application Load Balancer, Lambda  
✅ **Database**: RDS PostgreSQL (Multi-AZ)  
✅ **Storage**: S3 with versioning and lifecycle policies  
✅ **Serverless**: Lambda, API Gateway, Step Functions  
✅ **Infrastructure**: CloudFormation + Terraform (hybrid approach)  
✅ **Security**: Security Groups, IAM Roles, Secrets Manager  
✅ **Monitoring**: CloudWatch Logs & Metrics  
✅ **Version Control**: GitHub with CI/CD pipeline  

## Bonus Features Implemented

🎁 **API Gateway**: RESTful API for Lambda invocation  
🎁 **Step Functions**: Automated workflow orchestration  
🎁 **CI/CD Pipeline**: GitHub Actions with AWS CodeDeploy  

## Scalability Features

- **Horizontal Scaling**: Auto Scaling Group (2-6 instances)
- **Database Scaling**: RDS Multi-AZ with read replicas (optional)
- **Content Delivery**: CloudFront edge locations worldwide
- **Serverless**: Lambda scales automatically to demand
- **Storage Scaling**: S3 unlimited scalability

## High Availability

- **Multi-AZ**: Resources across 2 Availability Zones
- **Load Balancing**: ALB distributes traffic
- **Database Failover**: Automatic RDS failover
- **Auto Recovery**: Auto Scaling replaces failed instances
- **Backup**: Automated RDS backups, S3 versioning

## Cost Optimization

- **Reserved Instances**: For predictable workloads
- **Spot Instances**: For non-critical workloads
- **Lambda**: Pay per execution
- **S3 Lifecycle**: Move old data to Glacier
- **CloudWatch**: 7-day log retention

## Deployment Methods

1. **Terraform**: Networking infrastructure (VPC, subnets, security groups)
2. **CloudFormation**: Application resources (EC2, RDS, Lambda, ALB)
3. **AWS CLI**: Resource management and validation
4. **Boto3**: Python automation scripts
5. **GitHub Actions**: CI/CD automation
