#!/bin/bash
set -e

echo "=== Git-Captain Application Deployment ==="
echo "Starting deployment at $(date)"

# Stop any existing app
pm2 stop git-captain 2>/dev/null || echo "No existing app to stop"
pm2 delete git-captain 2>/dev/null || echo "No existing app to delete"

# Clean up existing installation
rm -rf /opt/git-captain
mkdir -p /opt/git-captain
cd /opt/git-captain

# Clone the repository
echo "Cloning Git-Captain repository..."
git clone https://github.com/Joe-Tavarez/Git-Captain.git .
git checkout feature/AWS || git checkout main

# Install dependencies
echo "Installing Node.js dependencies..."
npm install --production

# Create .env file from AWS Secrets Manager or use defaults
echo "Creating .env file..."
cat > .env << 'EOF'
# Git-Captain Environment Configuration
client_id=${GITHUB_CLIENT_ID:-}
client_secret=${GITHUB_CLIENT_SECRET:-}
GITHUB_ORG_NAME=${GITHUB_ORG_NAME:-ConfusedDeer}
GIT_PORT_ENDPOINT=${GIT_PORT_ENDPOINT:-http://localhost}
PORT=3000
privateKeyPath=./controllers/theKey.key
certificatePath=./controllers/theCert.cert
GIT_CAPTAIN_STATUS=up
GIT_CAPTAIN_REASON=Service is operational on AWS
TIMEOUT_MINUTES=25
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX=60
SESSION_TIMEOUT=1800000
NODE_ENV=production
EOF

# Create dummy SSL certificates if they don't exist (for HTTP mode)
if [ ! -f controllers/theKey.key ]; then
    echo "Creating placeholder SSL files..."
    touch controllers/theKey.key
    touch controllers/theCert.cert
fi

# Set proper permissions
chown -R ec2-user:ec2-user /opt/git-captain

# Start with PM2
echo "Starting application with PM2..."
pm2 start controllers/server.js --name git-captain \
    --node-args="--max-old-space-size=384" \
    --log /var/log/git-captain.log \
    --error /var/log/git-captain-error.log

# Configure PM2 to start on system boot
pm2 startup systemd -u root --hp /root
pm2 save

# Display status
pm2 list
pm2 logs git-captain --lines 20 --nostream

echo "=== Deployment complete at $(date) ==="
echo "Application should be accessible on port 3000"
