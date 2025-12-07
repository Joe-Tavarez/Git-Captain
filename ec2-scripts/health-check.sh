#!/bin/bash
###############################################################################
# Git-Captain Health Check Script
# Used by ALB to determine instance health
###############################################################################

# Check if Node.js process is running
if ! pgrep -f "node.*server.js" > /dev/null; then
    echo "Node.js process not running"
    exit 1
fi

# Check if application responds to health endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "Health check passed"
    exit 0
else
    echo "Health check failed with HTTP code: $HTTP_CODE"
    exit 1
fi
