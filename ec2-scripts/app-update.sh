#!/bin/bash
###############################################################################
# Git-Captain Application Update Script
# This script performs zero-downtime deployment updates
###############################################################################

set -e
exec > >(tee /var/log/git-captain-update.log)
exec 2>&1

echo "======================================"
echo "Starting Git-Captain Update"
echo "Time: $(date)"
echo "======================================"

cd /opt/git-captain

# Pull latest code from repository
echo "[1/5] Pulling latest code from repository..."
git fetch origin
git pull origin master

# Install/update dependencies
echo "[2/5] Updating Node.js dependencies..."
npm install --production

# Update secrets from AWS Secrets Manager
echo "[3/5] Refreshing secrets from AWS Secrets Manager..."
REGION=$(ec2-metadata --availability-zone | sed 's/.*placement: \(.*\).$/\1/' | sed 's/.$//')
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id git-captain/prod --region $REGION --query SecretString --output text)
echo "$SECRET_JSON" | jq -r 'to_entries|map("\(.key)=\(.value)")|.[]' > /opt/git-captain/.env

# Update SSL certificates from S3 if available
echo "[4/5] Checking for updated SSL certificates..."
aws s3 cp s3://git-captain-ssl-certs/theKey.key /opt/git-captain/controllers/theKey.key || echo "No SSL cert update"
aws s3 cp s3://git-captain-ssl-certs/theCert.cert /opt/git-captain/controllers/theCert.cert || echo "No SSL cert update"

# Reload application with PM2 (zero downtime)
echo "[5/5] Reloading application with PM2..."
cd /opt/git-captain/controllers
pm2 reload git-captain --update-env

# Verify health
sleep 3
curl -f http://localhost:3000/health && echo "Application health check passed!" || echo "Health check failed!"

echo "======================================"
echo "Git-Captain Update Complete!"
echo "Time: $(date)"
echo "======================================"

pm2 list
