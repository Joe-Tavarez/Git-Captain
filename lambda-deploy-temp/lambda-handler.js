/**
 * AWS Lambda Handler for Git-Captain
 * Wraps the Express app for serverless deployment
 */

require('dotenv').config();
const serverless = require('serverless-http');
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();

// Simple configuration from environment
const config = {
    gitHub: {
        gitHubAPIendpoint: 'https://api.github.com',
        gitHubEndPoint: 'https://github.com/login/oauth/access_token',
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        orgName: process.env.GITHUB_ORG_NAME || 'ConfusedDeer'
    }
};

let authCode;

// Basic middleware (avoid complex middleware that requires req/res context at init)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

console.log('Lambda handler initialized');

// Static files
app.use(express.static(path.join(__dirname, 'public')));

console.log('Lambda handler initialized');

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        service: 'git-captain',
        environment: process.env.NODE_ENV || 'production',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        runtime: 'AWS Lambda'
    });
});

// Simple GitHub API helper
async function makeGitHubRequest(url, token, method = 'GET', body = null) {
    const axios = require('axios');
    const options = {
        method,
        url,
        headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Git-Captain'
        }
    };
    if (body) options.data = body;
    const response = await axios(options);
    return response.data;
}

async function makeGitHubOAuthRequest(params) {
    const axios = require('axios');
    const response = await axios.post(config.gitHub.gitHubEndPoint, params, {
        headers: { 'Accept': 'application/json' }
    });
    return response.data;
}

// Main POST endpoint for branch operations
app.post('/:appName/:webServ', 
    generalLimiter,
    validation.branchOperation,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            const authorizationCode = req.body.authCode || authCode;
            const branchName = req.body.branchName;
            const operation = req.body.operation || 'create';

            logger.info('Branch operation request', {
                appName,
                webServ,
                operation,
                branchName,
                hasAuthCode: !!authorizationCode
            });

            if (!authorizationCode) {
                return res.status(401).json({
                    error: 'Unauthorized',
                    message: 'Authorization code required'
                });
            }

            // Get OAuth token
            const tokenData = await makeGitHubOAuthRequest({
                client_id,
                client_secret,
                code: authorizationCode
            });

            if (!tokenData.access_token) {
                return res.status(401).json({
                    error: 'Authentication failed',
                    message: 'Could not obtain access token'
                });
            }

            const accessToken = tokenData.access_token;
            authCode = authorizationCode; // Cache for subsequent requests

            // Perform branch operation based on type
            let result;
            switch (operation.toLowerCase()) {
                case 'create':
                    result = await createBranch(appName, branchName, accessToken);
                    break;
                case 'delete':
                    result = await deleteBranch(appName, branchName, accessToken);
                    break;
                case 'search':
                case 'get':
                    result = await getBranch(appName, branchName, accessToken);
                    break;
                default:
                    return res.status(400).json({
                        error: 'Invalid operation',
                        message: `Operation '${operation}' not supported`
                    });
            }

            res.json(result);

        } catch (error) {
            logger.error('Branch operation error', {
                error: error.message,
                stack: error.stack
            });
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// API v1 endpoint
app.post('/api/v1/:appName?/:webServ?', [
    strictLimiter,
    validation.branchOperation,
    handleValidationErrors
], async (req, res) => {
    // Similar to above but with stricter rate limiting
    res.redirect(307, `/${req.params.appName}/${req.params.webServ}`);
});

// DELETE endpoint for branch deletion
app.delete('/:appName?/:webServ?', 
    generalLimiter,
    validation.branchOperation,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            const branchName = req.query.branchName || req.body.branchName;
            const authorizationCode = req.query.authCode || req.body.authCode || authCode;

            if (!authorizationCode) {
                return res.status(401).json({
                    error: 'Unauthorized',
                    message: 'Authorization code required'
                });
            }

            const tokenData = await makeGitHubOAuthRequest({
                client_id,
                client_secret,
                code: authorizationCode
            });

            const result = await deleteBranch(appName, branchName, tokenData.access_token);
            res.json(result);

        } catch (error) {
            logger.error('Delete branch error', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// GET endpoint for branch search
app.get('/:appName?/:webServ?', 
    generalLimiter,
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            const branchName = req.query.branchName;
            const authorizationCode = req.query.authCode || authCode;

            if (!branchName) {
                // Serve the main HTML page
                return res.sendFile(path.join(__dirname, 'public/views/index.html'));
            }

            if (!authorizationCode) {
                return res.status(401).json({
                    error: 'Unauthorized',
                    message: 'Authorization code required'
                });
            }

            const tokenData = await makeGitHubOAuthRequest({
                client_id,
                client_secret,
                code: authorizationCode
            });

            const result = await getBranch(appName, branchName, tokenData.access_token);
            res.json(result);

        } catch (error) {
            logger.error('Get branch error', error);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// Catch-all route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/views/index.html'));
});

// Helper functions
async function createBranch(repoName, branchName, accessToken) {
    const repoPath = `repos/${orgName}/${repoName}`;
    
    // Get the default branch SHA
    const repoData = await makeGitHubRequest(`${gitHubAPIendpoint}/${repoPath}`, accessToken);
    const defaultBranch = repoData.default_branch;
    
    // Get the SHA of the default branch
    const refData = await makeGitHubRequest(
        `${gitHubAPIendpoint}/${repoPath}/git/refs/heads/${defaultBranch}`,
        accessToken
    );
    const sha = refData.object.sha;
    
    // Create new branch
    const result = await makeGitHubRequest(
        `${gitHubAPIendpoint}/${repoPath}/git/refs`,
        accessToken,
        'POST',
        {
            ref: `refs/heads/${branchName}`,
            sha: sha
        }
    );
    
    return {
        success: true,
        message: `Branch '${branchName}' created successfully`,
        branch: result
    };
}

async function deleteBranch(repoName, branchName, accessToken) {
    const repoPath = `repos/${orgName}/${repoName}`;
    
    const result = await makeGitHubRequest(
        `${gitHubAPIendpoint}/${repoPath}/git/refs/heads/${branchName}`,
        accessToken,
        'DELETE'
    );
    
    return {
        success: true,
        message: `Branch '${branchName}' deleted successfully`
    };
}

async function getBranch(repoName, branchName, accessToken) {
    const repoPath = `repos/${orgName}/${repoName}`;
    
    const branch = await makeGitHubRequest(
        `${gitHubAPIendpoint}/${repoPath}/branches/${branchName}`,
        accessToken
    );
    
    return {
        success: true,
        branch: branch
    };
}

// Export Lambda handler
module.exports.handler = serverless(app, {
    binary: ['image/*', 'font/*', 'application/octet-stream']
});
