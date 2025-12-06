# Git-Captain Deployment Helper
# Helps you choose the best deployment method

Write-Host @"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║              🚢 Git-Captain Deployment Helper              ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "Choose your deployment method:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. ⭐ AWS Serverless (Recommended)" -ForegroundColor Green
Write-Host "     - Zero server management" -ForegroundColor Gray
Write-Host "     - Auto-scaling, 99.99% uptime" -ForegroundColor Gray
Write-Host "     - ~`$2/month cost" -ForegroundColor Gray
Write-Host "     - 5-minute setup" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. 💻 Local Development" -ForegroundColor Cyan
Write-Host "     - Run on your machine" -ForegroundColor Gray
Write-Host "     - For testing and development" -ForegroundColor Gray
Write-Host "     - Free (uses your computer)" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. 📚 View Documentation" -ForegroundColor Magenta
Write-Host "     - Read deployment guides" -ForegroundColor Gray
Write-Host "     - Architecture overview" -ForegroundColor Gray
Write-Host "     - Troubleshooting help" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. ❌ Exit" -ForegroundColor Red
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  AWS Serverless Deployment" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        # Check prerequisites
        Write-Host "Checking prerequisites..." -ForegroundColor Yellow
        
        $hasAWSCLI = $null -ne (Get-Command aws -ErrorAction SilentlyContinue)
        $hasSAMCLI = $null -ne (Get-Command sam -ErrorAction SilentlyContinue)
        $hasNode = $null -ne (Get-Command node -ErrorAction SilentlyContinue)
        
        Write-Host "  AWS CLI:     $(if($hasAWSCLI){'✓ Installed'}else{'✗ Missing'})" -ForegroundColor $(if($hasAWSCLI){'Green'}else{'Red'})
        Write-Host "  SAM CLI:     $(if($hasSAMCLI){'✓ Installed'}else{'✗ Missing'})" -ForegroundColor $(if($hasSAMCLI){'Green'}else{'Red'})
        Write-Host "  Node.js:     $(if($hasNode){'✓ Installed'}else{'✗ Missing'})" -ForegroundColor $(if($hasNode){'Green'}else{'Red'})
        Write-Host ""
        
        if (-not $hasAWSCLI -or -not $hasSAMCLI -or -not $hasNode) {
            Write-Host "⚠️  Missing prerequisites. Install them first:" -ForegroundColor Yellow
            Write-Host ""
            if (-not $hasNode) {
                Write-Host "  Node.js:  https://nodejs.org/" -ForegroundColor Gray
            }
            if (-not $hasAWSCLI) {
                Write-Host "  AWS CLI:  https://aws.amazon.com/cli/" -ForegroundColor Gray
            }
            if (-not $hasSAMCLI) {
                Write-Host "  SAM CLI:  pip install aws-sam-cli" -ForegroundColor Gray
            }
            Write-Host ""
            Write-Host "After installing, run this script again." -ForegroundColor Yellow
            pause
            return
        }
        
        Write-Host "✓ All prerequisites installed!" -ForegroundColor Green
        Write-Host ""
        
        $confirm = Read-Host "Ready to deploy? This will create AWS resources (~`$2/month). Continue? (Y/N)"
        
        if ($confirm -eq "Y" -or $confirm -eq "y") {
            Write-Host ""
            Write-Host "Starting deployment..." -ForegroundColor Green
            Write-Host ""
            & .\deploy-serverless.ps1
        } else {
            Write-Host "Deployment cancelled." -ForegroundColor Yellow
        }
    }
    
    "2" {
        Write-Host ""
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Local Development Setup" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        # Check if Node.js is installed
        $hasNode = $null -ne (Get-Command node -ErrorAction SilentlyContinue)
        
        if (-not $hasNode) {
            Write-Host "✗ Node.js not found!" -ForegroundColor Red
            Write-Host ""
            Write-Host "Install Node.js first: https://nodejs.org/" -ForegroundColor Yellow
            pause
            return
        }
        
        Write-Host "✓ Node.js installed" -ForegroundColor Green
        Write-Host ""
        Write-Host "Setting up local environment..." -ForegroundColor Yellow
        Write-Host ""
        
        # Install dependencies
        Write-Host "1. Installing dependencies..." -ForegroundColor Cyan
        npm install
        
        # Check for .env file
        if (-not (Test-Path ".env")) {
            Write-Host ""
            Write-Host "2. Creating .env file..." -ForegroundColor Cyan
            Write-Host ""
            Write-Host "You'll need to provide some information:" -ForegroundColor Yellow
            Write-Host ""
            
            $clientId = Read-Host "GitHub OAuth Client ID"
            $clientSecret = Read-Host "GitHub OAuth Client Secret"
            $orgName = Read-Host "GitHub Organization/Username"
            
            $envContent = @"
# Git-Captain Environment Configuration

# GitHub OAuth Configuration
client_id=$clientId
client_secret=$clientSecret

# GitHub Organization/Username
GITHUB_ORG_NAME=$orgName

# Server Configuration
GIT_PORT_ENDPOINT=https://localhost
PORT=3000

# SSL Certificate Paths
privateKeyPath=./controllers/theKey.key
certificatePath=./controllers/theCert.cert

# Application Settings
GIT_CAPTAIN_STATUS=up
GIT_CAPTAIN_REASON=Service is operational
TIMEOUT_MINUTES=25

# Security Settings
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX=60
SESSION_TIMEOUT=1800000

# Environment
NODE_ENV=development
"@
            
            Set-Content -Path ".env" -Value $envContent
            Write-Host "✓ .env file created" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "2. .env file already exists" -ForegroundColor Green
        }
        
        # Generate SSL certificates
        Write-Host ""
        Write-Host "3. Generating SSL certificates..." -ForegroundColor Cyan
        
        if (Test-Path "controllers/theKey.key") {
            Write-Host "   Certificates already exist" -ForegroundColor Yellow
        } else {
            try {
                & "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" req -x509 -newkey rsa:2048 -nodes -keyout controllers/theKey.key -out controllers/theCert.cert -days 365 -subj "/CN=localhost"
                Write-Host "✓ SSL certificates generated" -ForegroundColor Green
            } catch {
                Write-Host "⚠️  Could not generate certificates automatically" -ForegroundColor Yellow
                Write-Host "   Install OpenSSL or generate manually" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════" -ForegroundColor Green
        Write-Host "  Setup Complete!" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "To start the server:" -ForegroundColor Yellow
        Write-Host "  npm start" -ForegroundColor White
        Write-Host ""
        Write-Host "Then visit:" -ForegroundColor Yellow
        Write-Host "  https://localhost:3000" -ForegroundColor White
        Write-Host ""
    }
    
    "3" {
        Write-Host ""
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Documentation" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Available guides:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  📖 README.md" -ForegroundColor White
        Write-Host "     Main project documentation" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  🚀 SERVERLESS_QUICKSTART.md" -ForegroundColor White
        Write-Host "     5-minute serverless deployment" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  📚 SERVERLESS_DEPLOYMENT.md" -ForegroundColor White
        Write-Host "     Complete serverless guide" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  📝 SERVERLESS_MIGRATION_SUMMARY.md" -ForegroundColor White
        Write-Host "     What was created and how to use it" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  🏗️  docs/aws/AWS_ARCHITECTURE.md" -ForegroundColor White
        Write-Host "     AWS infrastructure details" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  🔧 lambda/README.md" -ForegroundColor White
        Write-Host "     Lambda functions documentation" -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "Opening README.md..." -ForegroundColor Yellow
        Start-Process "README.md"
    }
    
    "4" {
        Write-Host ""
        Write-Host "Goodbye! 👋" -ForegroundColor Cyan
        return
    }
    
    default {
        Write-Host ""
        Write-Host "Invalid choice. Please run the script again." -ForegroundColor Red
    }
}

Write-Host ""
pause
