#!/bin/bash
###############################################################################
# Git-Captain EC2 User Data Bootstrap Script
# This script runs on EC2 instance first launch to setup the Node.js application
###############################################################################

set -e  # Exit on error
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "======================================"
echo "Starting Git-Captain Bootstrap"
echo "Time: $(date)"
echo "======================================"

# Update system packages
echo "[1/10] Updating system packages..."
yum update -y

# Install Node.js 18.x
echo "[2/10] Installing Node.js 18.x..."
curl -sL https://rpm.nodesource.com/setup_18.x | bash -
yum install -y nodejs

# Install Git
echo "[3/10] Installing Git..."
yum install -y git

# Install PM2 globally for process management
echo "[4/10] Installing PM2..."
npm install -g pm2

# Create application directory
echo "[5/10] Creating application directory..."
mkdir -p /opt/git-captain
cd /opt/git-captain

# Clone Git-Captain repository
echo "[6/10] Cloning Git-Captain repository..."
# Replace with your actual repository URL
git clone https://github.com/Joe-Tavarez/Git-Captain.git .

# Install Node.js dependencies
echo "[7/10] Installing Node.js dependencies..."
npm install --production

# Retrieve environment variables from AWS Secrets Manager
echo "[8/10] Retrieving secrets from AWS Secrets Manager..."
REGION=$(ec2-metadata --availability-zone | sed 's/.*placement: \(.*\).$/\1/' | sed 's/.$//')
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id git-captain/prod --region $REGION --query SecretString --output text)

# Create .env file from secrets
echo "$SECRET_JSON" | jq -r 'to_entries|map("\(.key)=\(.value)")|.[]' > /opt/git-captain/.env

# Retrieve SSL certificates from S3 (if using custom certs)
echo "[9/10] Retrieving SSL certificates from S3..."
aws s3 cp s3://git-captain-ssl-certs/theKey.key /opt/git-captain/controllers/theKey.key || echo "No custom SSL cert in S3, skipping..."
aws s3 cp s3://git-captain-ssl-certs/theCert.cert /opt/git-captain/controllers/theCert.cert || echo "No custom SSL cert in S3, skipping..."

# Update .env with correct certificate paths
sed -i 's|privateKeyPath=.*|privateKeyPath=/opt/git-captain/controllers/theKey.key|g' /opt/git-captain/.env
sed -i 's|certificatePath=.*|certificatePath=/opt/git-captain/controllers/theCert.cert|g' /opt/git-captain/.env

# Install and configure CloudWatch Logs agent
echo "[10/10] Installing CloudWatch Logs agent..."
yum install -y amazon-cloudwatch-agent

# Create CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/git-captain/logs/application-*.log",
            "log_group_name": "/aws/ec2/git-captain/application",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/git-captain/logs/error-*.log",
            "log_group_name": "/aws/ec2/git-captain/errors",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/aws/ec2/git-captain/bootstrap",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

# Create logs directory
mkdir -p /opt/git-captain/logs
chown -R ec2-user:ec2-user /opt/git-captain

# Start application with PM2
echo "Starting Git-Captain application with PM2..."
cd /opt/git-captain/controllers
su - ec2-user -c "cd /opt/git-captain/controllers && pm2 start server.js --name git-captain"
su - ec2-user -c "pm2 save"

# Configure PM2 to start on boot
env PATH=$PATH:/usr/bin pm2 startup systemd -u ec2-user --hp /home/ec2-user
systemctl enable pm2-ec2-user

echo "======================================"
echo "Git-Captain Bootstrap Complete!"
echo "Time: $(date)"
echo "======================================"

# Verify application is running
sleep 5
pm2 list
curl -f http://localhost:3000/health || echo "Health check failed - application may need time to start"
