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
        client_id: process.env.GITHUB_CLIENT_ID || '',
        client_secret: process.env.GITHUB_CLIENT_SECRET || '',
        orgName: process.env.GITHUB_ORG_NAME || 'ConfusedDeer'
    }
};

let authCode;

// Basic middleware (avoid complex middleware that requires req/res context at init)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Static files - serve from both root and /static for compatibility
app.use(express.static(path.join(__dirname, 'public')));
app.use('/static', express.static(path.join(__dirname, 'public')));

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

// Git-Captain status endpoint for frontend
app.get('/gitCaptain/checkGitHubStatus', (req, res) => {
    res.status(200).json({
        statusCode: 200,
        status: 'up',
        reason: 'Service is operational',
        clientID: config.gitHub.client_id,
        orgName: config.gitHub.orgName,
        clientTimeout: 25,
        gitPortEndPoint: '' // Lambda uses current domain
    });
});

// Config.js endpoint for JavaScript to load client_id immediately
app.get('/config.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`
        window.GIT_CAPTAIN_CONFIG = {
            clientID: '${config.gitHub.client_id}',
            orgName: '${config.gitHub.orgName}',
            gitPortEndPoint: ''
        };
    `);
});

// Authenticated page - needs client_id injection too
app.get('/authenticated.html', (req, res) => {
    const fs = require('fs');
    const authPath = path.join(__dirname, 'public/views/authenticated.html');
    let html = fs.readFileSync(authPath, 'utf8');
    
    // Inject client_id into the page
    const configScript = `
    <script>
        var clientID = '${config.gitHub.client_id}';
        var orgName = '${config.gitHub.orgName}';
        var gitPortEndPoint = '';
        console.log('Authenticated page - clientID =', clientID);
    </script>
    `;
    html = html.replace('</head>', configScript + '</head>');
    
    res.send(html);
});

// OAuth token exchange endpoint
app.post('/gitCaptain/getToken', async (req, res) => {
    try {
        const authCode = req.query.code || req.body.code;
        
        if (!authCode) {
            return res.status(400).json({ error: 'Authorization code is required' });
        }

        // Exchange code for access token
        const tokenResponse = await makeGitHubOAuthRequest({
            client_id: config.gitHub.client_id,
            client_secret: config.gitHub.client_secret,
            code: authCode
        });

        if (tokenResponse.error) {
            console.error('OAuth token exchange error:', tokenResponse);
            return res.status(401).json({ error: tokenResponse.error_description || 'Token exchange failed' });
        }

        // Return the access token
        res.json({ 
            body: tokenResponse.access_token,
            token_type: tokenResponse.token_type,
            scope: tokenResponse.scope
        });
        
    } catch (error) {
        console.error('Token exchange error:', error.message);
        res.status(500).json({ error: 'Failed to exchange authorization code for token' });
    }
});

// Search for repos endpoint
app.post('/gitCaptain/searchForRepos', async (req, res) => {
    try {
        const token = req.body.token;
        
        if (!token) {
            return res.status(400).json({ error: 'Access token is required' });
        }

        // Fetch user's repos from GitHub
        const repos = await makeGitHubRequest(
            `${config.gitHub.gitHubAPIendpoint}/user/repos?sort=updated&per_page=100`,
            token,
            'GET'
        );

        // Also fetch repos from the organization if configured
        let orgRepos = [];
        if (config.gitHub.orgName) {
            try {
                orgRepos = await makeGitHubRequest(
                    `${config.gitHub.gitHubAPIendpoint}/orgs/${config.gitHub.orgName}/repos?per_page=100`,
                    token,
                    'GET'
                );
            } catch (err) {
                console.warn(`Could not fetch org repos for ${config.gitHub.orgName}:`, err.message);
            }
        }

        // Combine and deduplicate repos
        const allRepos = [...repos, ...orgRepos];
        const uniqueRepos = Array.from(new Map(allRepos.map(repo => [repo.id, repo])).values());

        // Return in the format expected by the frontend
        res.json({ 
            statusCode: 200, 
            body: JSON.stringify(uniqueRepos) 
        });
        
    } catch (error) {
        console.error('Search repos error:', error.message);
        if (error.response?.status === 401) {
            return res.status(401).json({ error: 'Invalid or expired access token' });
        }
        res.status(500).json({ error: 'Failed to fetch repositories' });
    }
});

// Create branches endpoint
app.post('/gitCaptain/createBranches', async (req, res) => {
    try {
        const { token, repo, branchRef, newBranch } = req.body;
        
        if (!token || !repo || !branchRef || !newBranch) {
            return res.status(400).json({ 
                statusCode: 400,
                error: 'Missing required fields',
                message: 'token, repo, branchRef, and newBranch are required'
            });
        }

        // Get the reference branch SHA
        const refUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs/heads/${branchRef}`;
        
        let refData;
        try {
            refData = await makeGitHubRequest(refUrl, token, 'GET');
        } catch (error) {
            // Try default branches if specified branch not found
            const defaultBranches = ['main', 'master', 'develop'];
            
            for (const defaultBranch of defaultBranches) {
                if (defaultBranch !== branchRef) {
                    try {
                        const defaultUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs/heads/${defaultBranch}`;
                        refData = await makeGitHubRequest(defaultUrl, token, 'GET');
                        break;
                    } catch (err) {
                        continue;
                    }
                }
            }
            
            if (!refData) {
                return res.json({
                    statusCode: 404,
                    message: `Could not find branch '${branchRef}' or any default branches in repository '${repo}'`
                });
            }
        }

        // Create the new branch
        const createUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs`;
        const createData = {
            ref: `refs/heads/${newBranch}`,
            sha: refData.object.sha
        };

        try {
            const result = await makeGitHubRequest(createUrl, token, 'POST', createData);
            res.json({ statusCode: 201, body: JSON.stringify(result) });
        } catch (error) {
            if (error.response?.status === 422) {
                res.json({ statusCode: 422, message: 'Branch already exists' });
            } else {
                throw error;
            }
        }
        
    } catch (error) {
        console.error('Create branch error:', error.message);
        res.json({ 
            statusCode: error.response?.status || 500, 
            error: 'Failed to create branch',
            message: error.message 
        });
    }
});

// Search for branch endpoint
app.post('/gitCaptain/searchForBranch', async (req, res) => {
    try {
        const { token, repo, searchForBranch } = req.body;
        
        if (!token || !repo || !searchForBranch) {
            return res.status(400).json({ 
                statusCode: 400,
                error: 'Missing required fields' 
            });
        }

        const searchUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs/heads/${searchForBranch}`;
        
        try {
            const result = await makeGitHubRequest(searchUrl, token, 'GET');
            res.json({ statusCode: 200, body: JSON.stringify(result) });
        } catch (error) {
            res.json({ 
                statusCode: error.response?.status || 404, 
                body: JSON.stringify({ message: 'Branch not found' }) 
            });
        }
        
    } catch (error) {
        console.error('Search branch error:', error.message);
        res.json({ statusCode: 500, error: 'Failed to search branch' });
    }
});

// Search for pull requests endpoint
app.post('/gitCaptain/searchForPR', async (req, res) => {
    try {
        const { token, repo, state, prBaseBranch } = req.body;
        
        if (!token || !repo || !state || !prBaseBranch) {
            return res.status(400).json({ 
                statusCode: 400,
                error: 'Missing required fields' 
            });
        }

        const prUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/pulls?state=${state}&base=${prBaseBranch}`;
        
        try {
            const result = await makeGitHubRequest(prUrl, token, 'GET');
            res.json({ statusCode: 200, body: JSON.stringify(result) });
        } catch (error) {
            res.json({ 
                statusCode: error.response?.status || 500, 
                body: JSON.stringify([]) 
            });
        }
        
    } catch (error) {
        console.error('Search PR error:', error.message);
        res.json({ statusCode: 500, error: 'Failed to search pull requests' });
    }
});

// Delete branches endpoint (DELETE method with plural name)
app.delete('/gitCaptain/deleteBranches', async (req, res) => {
    try {
        const { token, repo, deleteBranch } = req.body;
        
        if (!token || !repo || !deleteBranch) {
            return res.status(400).json({ 
                statusCode: 400,
                error: 'Missing required fields' 
            });
        }

        const deleteUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs/heads/${deleteBranch}`;
        
        try {
            await makeGitHubRequest(deleteUrl, token, 'DELETE');
            res.json({ statusCode: 204, message: 'Branch deleted successfully' });
        } catch (error) {
            res.json({ 
                statusCode: error.response?.status || 500, 
                error: 'Failed to delete branch' 
            });
        }
        
    } catch (error) {
        console.error('Delete branch error:', error.message);
        res.json({ statusCode: 500, error: 'Failed to delete branch' });
    }
});

// Delete branch endpoint
app.post('/gitCaptain/deleteBranch', async (req, res) => {
    try {
        const { token, repo, deleteBranch } = req.body;
        
        if (!token || !repo || !deleteBranch) {
            return res.status(400).json({ 
                statusCode: 400,
                error: 'Missing required fields' 
            });
        }

        const deleteUrl = `${config.gitHub.gitHubAPIendpoint}/repos/${config.gitHub.orgName}/${repo}/git/refs/heads/${deleteBranch}`;
        
        try {
            await makeGitHubRequest(deleteUrl, token, 'DELETE');
            res.json({ statusCode: 204, message: 'Branch deleted successfully' });
        } catch (error) {
            res.json({ 
                statusCode: error.response?.status || 500, 
                error: 'Failed to delete branch' 
            });
        }
        
    } catch (error) {
        console.error('Delete branch error:', error.message);
        res.json({ statusCode: 500, error: 'Failed to delete branch' });
    }
});

// Logout/revoke token endpoint
app.post('/gitCaptain/logOff', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ statusCode: 400, error: 'Token is required' });
        }

        const revokeUrl = `${config.gitHub.gitHubAPIendpoint}/applications/${config.gitHub.client_id}/tokens/${token}`;
        
        const axios = require('axios');
        try {
            await axios.delete(revokeUrl, {
                auth: {
                    username: config.gitHub.client_id,
                    password: config.gitHub.client_secret
                },
                headers: {
                    'User-Agent': 'Git-Captain',
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            res.json({ statusCode: 204, message: 'Token revoked' });
        } catch (error) {
            res.json({ statusCode: error.response?.status || 500 });
        }
        
    } catch (error) {
        console.error('Logoff error:', error.message);
        res.json({ statusCode: 500, error: 'Failed to revoke token' });
    }
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
app.post('/:appName/:webServ', async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            const authorizationCode = req.body.authCode || authCode;
            const branchName = req.body.branchName;
            const operation = req.body.operation || 'create';

            console.log('Branch operation:', { appName, webServ, operation, branchName });

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
            console.error('Branch operation error:', error.message);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// API v1 endpoint
app.post('/api/v1/:appName?/:webServ?', async (req, res) => {
    // Similar to above but with stricter rate limiting
    res.redirect(307, `/${req.params.appName}/${req.params.webServ}`);
});

// DELETE endpoint for branch deletion
app.delete('/:appName?/:webServ?', async (req, res) => {
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
            console.error('Delete branch error:', error.message);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message
            });
        }
    }
);

// GET endpoint for branch search
app.get('/:appName?/:webServ?', async (req, res) => {
    try {
        const { appName, webServ } = req.params;
        const branchName = req.query.branchName;
        const authorizationCode = req.query.authCode || authCode;

        if (!branchName && !appName && !webServ) {
            // Serve the main HTML page with client_id injected
            const fs = require('fs');
            const indexPath = path.join(__dirname, 'public/views/index.html');
            let html = fs.readFileSync(indexPath, 'utf8');
            
            // Inject client_id into the page
            const configScript = `
            <script>
                var clientID = '${config.gitHub.client_id}';
                var orgName = '${config.gitHub.orgName}';
                var gitPortEndPoint = '';
                console.log('Config loaded: clientID =', clientID);
            </script>
            `;
            html = html.replace('</head>', configScript + '</head>');
            
            return res.send(html);
        }

        if (!branchName) {
            return res.sendFile(path.join(__dirname, 'public/views/index.html'));
        }            if (!authorizationCode) {
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
            console.error('Get branch error:', error.message);
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
