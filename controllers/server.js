/**
 * Created by JoeTavarez on 7/6/18.
 * Updated with modern security and dependencies - 7/10/25
 */

require('dotenv').config();

const config = require('./config');
const { makeGitHubRequest, makeGitHubOAuthRequest, makeHttpRequest } = require('./httpClient');
const { validation, handleValidationErrors } = require('./validation');
const { validationResult } = require('express-validator');
const {
    helmet,
    cors,
    compression,
    generalLimiter,
    strictLimiter,
    authLimiter,
    securityMiddleware,
    requestLogger
} = require('./middleware');
const logger = require('./logger');

const https = require('https');
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();

let authCode;

// Configuration constants
const gitHubAPIendpoint = config.gitHub.gitHubAPIendpoint;
const gitHubEndPoint = config.gitHub.gitHubEndPoint;
const client_id = config.gitHub.client_id;
const client_secret = config.gitHub.client_secret;
const gitCaptainStatus = config.web.gitCaptainStatus;
const gitCaptainReason = config.web.gitCaptainReason;
const orgName = config.gitHub.orgName;
const clientTimeOut = config.web.gitCaptainTimeOutInMinutes;

// SSL Configuration
let privateKey, certificate, credentials;
try {
    privateKey = fs.readFileSync(config.web.privateKeyPath, 'utf8');
    certificate = fs.readFileSync(config.web.certificatePath, 'utf8');
    credentials = { key: privateKey, cert: certificate };
    logger.info('SSL certificates loaded successfully');
} catch (error) {
    logger.error('Failed to load SSL certificates', { error: error.message });
    process.exit(1);
}

app.set('port', config.web.port);

// Security middleware - applied first
app.use(helmet);
app.use(cors);
app.use(compression);
app.use(securityMiddleware);
app.use(requestLogger);

// Rate limiting - applied to all routes
app.use(generalLimiter);

// Static file serving
app.use('/static', express.static(path.join(__dirname, '../', '/public')));
app.use(express.static(path.join(__dirname, '../', '/public/views')));

// Body parsing middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy for rate limiting and IP detection
app.set('trust proxy', 1);

////////////////////////////////////////////////////////////////Health Check Endpoint/////////////////////////////////////////////////////////////////////
// Health check endpoint for ALB target group
app.get('/health', (req, res) => {
    const healthCheck = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
            rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
        },
        environment: process.env.NODE_ENV || 'development',
        version: '2.0.0'
    };
    
    res.status(200).json(healthCheck);
});

////////////////////////////////////////////////////////////////app.post starts/////////////////////////////////////////////////////////////////////
// Main POST route for all gitCaptain endpoints
app.post('/:appName/:webServ', 
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            
            // Debug logging
            logger.info('POST request received', {
                url: req.url,
                appName,
                webServ,
                params: req.params,
                body: req.body ? Object.keys(req.body) : 'no body',
                appNameCheck: appName === 'gitCaptain',
                webServCheck: webServ === 'searchForBranch',
                bothCheck: appName === 'gitCaptain' && webServ === 'searchForBranch',
                webServValue: webServ,
                webServTypeOf: typeof webServ
            });

            if (appName === 'gitCaptain' && webServ === 'getToken') {
                logger.info('Matched getToken endpoint');
                // Handle AJAX requests from authenticated.html for token exchange
                try {
                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const authCode = req.query.code;
                    if (!authCode) {
                        return res.status(400).json({
                            error: 'Missing authorization code',
                            message: 'OAuth authorization code is required'
                        });
                    }

                    const urlForToken = gitHubEndPoint + "/login/oauth/access_token" + "?client_id=" + client_id + "&client_secret=" + client_secret + "&code=" + authCode + "&scope=repo";

                    const options = {
                        method: 'POST',
                        url: urlForToken,
                        headers: {
                            'User-Agent': 'Git-Captain',
                            'Accept': 'application/x-www-form-urlencoded'
                        }
                    };

                    const tokenResponse = await makeGitHubOAuthRequest(options);
                    
                    if (tokenResponse.statusCode === 200) {
                        // Return in the format expected by the client (matching original request library format)
                        res.status(200).json({
                            statusCode: 200,
                            body: tokenResponse.body
                        });
                    } else {
                        logger.error('OAuth token exchange failed', {
                            statusCode: tokenResponse.statusCode,
                            body: tokenResponse.body
                        });
                        res.status(tokenResponse.statusCode).json({
                            error: 'OAuth token exchange failed',
                            message: 'Failed to exchange authorization code for access token'
                        });
                    }
                } catch (error) {
                    logger.error('OAuth token exchange error', {
                        error: error.message,
                        stack: error.stack,
                        code: req.query.code
                    });
                    res.status(500).json({
                        error: 'OAuth token exchange error',
                        message: 'An error occurred during token exchange'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'searchForRepos') {
                logger.info('Matched searchForRepos endpoint');
                // Handle repository search requests
                try {
                    // Validate request body
                    await Promise.all(validation.searchRepos.map(validator => validator.run(req)));
                    const errors = validationResult(req);
                    if (!errors.isEmpty()) {
                        return res.status(400).json({
                            error: 'Validation failed',
                            message: 'Invalid input data',
                            details: errors.array()
                        });
                    }

                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const urlForRepoSearch = gitHubAPIendpoint + "/user/repos";

                    const options = {
                        method: 'GET',
                        url: urlForRepoSearch
                    };

                    const repoResponse = await makeGitHubRequest(options, req.body.token);
                    res.status(repoResponse.statusCode).json({
                        statusCode: repoResponse.statusCode,
                        body: repoResponse.body
                    });
                } catch (error) {
                    logger.error('Repository search error', {
                        error: error.message,
                        stack: error.stack,
                        token: req.body.token ? '[PRESENT]' : '[MISSING]'
                    });
                    res.status(500).json({
                        error: 'Repository search error',
                        message: 'An error occurred during repository search'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'createBranches') {
                logger.info('Matched createBranches endpoint');
                logger.info('ENTERING createBranches handler', { appName, webServ });
                // Handle branch creation requests
                logger.info('Processing createBranches request', {
                    appName,
                    webServ,
                    hasBody: !!req.body,
                    bodyKeys: req.body ? Object.keys(req.body) : 'no body'
                });
                
                try {
                    // Validate request body
                    await Promise.all(validation.createBranch.map(validator => validator.run(req)));
                    const errors = validationResult(req);
                    if (!errors.isEmpty()) {
                        return res.status(400).json({
                            error: 'Validation failed',
                            message: 'Invalid input data',
                            details: errors.array()
                        });
                    }

                    // Skip additional auth rate limiting for createBranches - already covered by general limiter

                    const urlForCreate = gitHubAPIendpoint + "/repos/" + orgName + "/" + req.body.repo + "/git/refs/heads/" + req.body.branchRef;

                    const options = {
                        method: 'GET',
                        url: urlForCreate
                    };

                    // First request to get branch reference
                    logger.info('Getting branch reference', { url: urlForCreate, repo: req.body.repo, branchRef: req.body.branchRef });
                    let refResponse = await makeGitHubRequest(options, req.body.token);
                    
                    logger.info('Branch reference response', { 
                        statusCode: refResponse.statusCode, 
                        hasBody: !!refResponse.body 
                    });
                    
                    // If the specified branch doesn't exist, try common defaults
                    if (refResponse.statusCode === 404) {
                        logger.info('Branch not found, trying default branches');
                        const defaultBranches = ['main', 'master', 'develop'];
                        
                        for (const defaultBranch of defaultBranches) {
                            if (defaultBranch !== req.body.branchRef) {
                                const defaultUrl = gitHubAPIendpoint + "/repos/" + orgName + "/" + req.body.repo + "/git/refs/heads/" + defaultBranch;
                                logger.info('Trying default branch', { defaultBranch, url: defaultUrl });
                                
                                const defaultOptions = {
                                    method: 'GET',
                                    url: defaultUrl
                                };
                                
                                refResponse = await makeGitHubRequest(defaultOptions, req.body.token);
                                
                                if (refResponse.statusCode === 200) {
                                    logger.info('Found default branch', { defaultBranch });
                                    break;
                                }
                            }
                        }
                    }
                    
                    if (refResponse.statusCode === 200) {
                        const myJSONobjRef = JSON.parse(refResponse.body);
                        logger.info('Found branch reference', { sha: myJSONobjRef.object?.sha });
                        
                        const urlForBranches = gitHubAPIendpoint + "/repos/" + orgName + "/" + req.body.repo + "/git/refs";

                        const branchOptions = {
                            method: 'POST',
                            url: urlForBranches,
                            body: {
                                ref: "refs/heads/" + req.body.newBranch,
                                sha: myJSONobjRef.object.sha
                            }
                        };

                        logger.info('Creating new branch', { 
                            url: urlForBranches, 
                            newBranch: req.body.newBranch, 
                            sha: myJSONobjRef.object.sha 
                        });
                        
                        const branchResponse = await makeGitHubRequest(branchOptions, req.body.token);
                        logger.info('Branch creation response', { statusCode: branchResponse.statusCode });
                        
                        if (branchResponse.body) {
                            res.status(200).json({
                                statusCode: branchResponse.statusCode,
                                body: branchResponse.body
                            });
                        } else {
                            res.status(200).json({ 
                                statusCode: branchResponse.statusCode 
                            });
                        }
                    } else {
                        logger.warn('Failed to get any branch reference', { 
                            statusCode: refResponse.statusCode, 
                            body: refResponse.body,
                            originalBranch: req.body.branchRef
                        });
                        
                        const errorResponse = {
                            statusCode: refResponse.statusCode,
                            message: `Could not find branch '${req.body.branchRef}' or any default branches (main, master, develop) in repository '${req.body.repo}'`
                        };
                        
                        if (refResponse.body) {
                            try {
                                const parsedBody = JSON.parse(refResponse.body);
                                errorResponse.details = parsedBody;
                            } catch (e) {
                                errorResponse.details = refResponse.body;
                            }
                        }
                        
                        res.status(200).json(errorResponse);
                    }
                } catch (error) {
                    logger.error('Branch creation error', {
                        error: error.message,
                        stack: error.stack,
                        token: req.body.token ? '[PRESENT]' : '[MISSING]'
                    });
                    res.status(500).json({
                        error: 'Branch creation error',
                        message: 'An error occurred during branch creation'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'searchForBranch') {
                logger.info('Matched searchForBranch endpoint');
                // Handle branch search requests
                try {
                    // Validate request body
                    await Promise.all(validation.searchBranch.map(validator => validator.run(req)));
                    const errors = validationResult(req);
                    if (!errors.isEmpty()) {
                        return res.status(400).json({
                            error: 'Validation failed',
                            message: 'Invalid input data',
                            details: errors.array()
                        });
                    }

                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const urlForSearch = gitHubAPIendpoint + "/repos/" + orgName + "/" + req.body.repo + "/git/refs/heads/" + req.body.searchForBranch;

                    const options = {
                        method: 'GET',
                        url: urlForSearch
                    };

                    const searchResponse = await makeGitHubRequest(options, req.body.token);
                    res.status(200).json({
                        statusCode: searchResponse.statusCode,
                        body: searchResponse.body
                    });
                } catch (error) {
                    logger.error('Branch search error', {
                        error: error.message,
                        stack: error.stack,
                        token: req.body.token ? '[PRESENT]' : '[MISSING]'
                    });
                    res.status(500).json({
                        error: 'Branch search error',
                        message: 'An error occurred during branch search'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'searchForPR') {
                // Handle pull request search requests
                try {
                    // Validate request body
                    await Promise.all(validation.searchPR.map(validator => validator.run(req)));
                    const errors = validationResult(req);
                    if (!errors.isEmpty()) {
                        return res.status(400).json({
                            error: 'Validation failed',
                            message: 'Invalid input data',
                            details: errors.array()
                        });
                    }

                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const urlForPRsearch = gitHubAPIendpoint + "/repos/" + orgName + "/" + req.body.repo + "/pulls?" + "state=" + req.body.state + "&base=" + req.body.prBaseBranch;

                    const options = {
                        method: 'GET',
                        url: urlForPRsearch
                    };

                    const prResponse = await makeGitHubRequest(options, req.body.token);
                    res.status(200).json({
                        statusCode: prResponse.statusCode,
                        body: prResponse.body
                    });
                } catch (error) {
                    logger.error('Pull request search error', {
                        error: error.message,
                        stack: error.stack,
                        token: req.body.token ? '[PRESENT]' : '[MISSING]'
                    });
                    res.status(500).json({
                        error: 'Pull request search error',
                        message: 'An error occurred during pull request search'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'logOff') {
                // Handle logout requests
                try {
                    // Validate request body
                    await Promise.all(validation.logOff.map(validator => validator.run(req)));
                    const errors = validationResult(req);
                    if (!errors.isEmpty()) {
                        return res.status(400).json({
                            error: 'Validation failed',
                            message: 'Invalid input data',
                            details: errors.array()
                        });
                    }

                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const urlForRevokeToken = gitHubAPIendpoint + "/applications/" + client_id + "/tokens/" + req.body.token;

                    const options = {
                        method: 'DELETE',
                        url: urlForRevokeToken,
                        auth: {
                            username: client_id,
                            password: client_secret
                        }
                    };

                    const logoffResponse = await makeGitHubOAuthRequest(options);
                    res.status(logoffResponse.statusCode).json(logoffResponse.body);
                } catch (error) {
                    logger.error('Logout error', {
                        error: error.message,
                        stack: error.stack,
                        token: req.body.token ? '[PRESENT]' : '[MISSING]'
                    });
                    res.status(500).json({
                        error: 'Logout error',
                        message: 'An error occurred during logout'
                    });
                }
            } else {
                logger.info('No endpoint matched - returning 404', {
                    appName,
                    webServ,
                    appNameType: typeof appName,
                    webServType: typeof webServ,
                    appNameEquals: appName === 'gitCaptain',
                    webServEquals: webServ === 'createBranches'
                });
                res.status(404).json({
                    error: 'Endpoint not found',
                    message: 'The requested endpoint does not exist'
                });
            }
        } catch (error) {
            logger.error('POST request error', {
                error: error.message,
                stack: error.stack,
                url: req.url,
                method: req.method,
                ip: req.ip
            });
            res.status(500).json({
                error: 'Internal server error',
                message: 'An unexpected error occurred'
            });
        }
    });

// Legacy /api/v1/ route - kept for backwards compatibility but endpoints moved to main route
app.post('/api/v1/:appName?/:webServ?', [
    validation.params,
    handleValidationErrors,
    strictLimiter
], async (req, res) => {
    // All endpoints have been moved to the main POST route for consistency
    res.status(404).json({
        error: 'Endpoints moved',
        message: 'This endpoint has been moved to the main route. Please use /gitCaptain/{endpoint} instead of /api/v1/gitCaptain/{endpoint}'
    });
});

// DELETE endpoint with modern async/await
app.delete('/:appName?/:webServ?', 
    generalLimiter,
    validation.deleteBranch,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;
            
            if (appName === 'gitCaptain' && webServ === 'deleteBranches') {
                // Validate request body
                if (!req.body.repo || !req.body.deleteBranch || !req.body.token) {
                    return res.status(400).json({
                        error: 'Missing required parameters',
                        message: 'repo, deleteBranch, and token are required'
                    });
                }

                const options = {
                    method: 'DELETE',
                    url: `${gitHubAPIendpoint}/repos/${orgName}/${req.body.repo}/git/refs/heads/${req.body.deleteBranch}`,
                    headers: {
                        'User-Agent': 'Git-Captain',
                        'Authorization': `token ${req.body.token.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")}`
                    }
                };

                const deleteResponse = await makeGitHubRequest(options, req.body.token);
                res.status(200).json({
                    statusCode: deleteResponse.statusCode,
                    body: deleteResponse.body || ''
                });
            } else {
                res.status(404).json({
                    error: 'Endpoint not found',
                    message: 'The requested endpoint does not exist'
                });
            }
        } catch (error) {
            logger.error('DELETE request error', {
                error: error.message,
                stack: error.stack,
                url: req.url,
                method: req.method,
                ip: req.ip
            });
            res.status(500).json({
                error: 'Internal server error',
                message: 'An unexpected error occurred'
            });
        }
    });

// GET endpoints with modern async/await
app.get('/:appName?/:webServ?', 
    generalLimiter,
    async (req, res) => {
        try {
            const { appName, webServ } = req.params;

            if (appName === 'gitCaptain' && webServ === 'checkGitHubStatus') {
                const options = {
                    method: 'GET',
                    url: 'https://status.github.com/api/last-message.json',
                    headers: {
                        'User-Agent': 'Git-Captain'
                    }
                };

                const statusResponse = await makeHttpRequest(options);
                res.json(statusResponse);
            } else if (appName === 'gitCaptain' && webServ === 'getToken') {
                // GitHub OAuth callback - handle the authorization code
                try {
                    // Apply auth rate limiting
                    await new Promise((resolve, reject) => {
                        authLimiter(req, res, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });

                    const authCode = req.query.code;
                    if (!authCode) {
                        return res.status(400).json({
                            error: 'Missing authorization code',
                            message: 'OAuth authorization code is required'
                        });
                    }

                    const urlForToken = gitHubEndPoint + "/login/oauth/access_token" + "?client_id=" + client_id + "&client_secret=" + client_secret + "&code=" + authCode + "&scope=repo";

                    const options = {
                        method: 'POST',
                        url: urlForToken,
                        headers: {
                            'User-Agent': 'Git-Captain',
                            'Accept': 'application/x-www-form-urlencoded'
                        }
                    };

                    const tokenResponse = await makeGitHubOAuthRequest(options);
                    
                    if (tokenResponse.statusCode === 200) {
                        // Redirect to authenticated page with token in URL
                        res.redirect(`/authenticated.html?code=${authCode}`);
                    } else {
                        logger.error('OAuth token exchange failed', {
                            statusCode: tokenResponse.statusCode,
                            body: tokenResponse.body
                        });
                        res.status(tokenResponse.statusCode).json({
                            error: 'OAuth token exchange failed',
                            message: 'Failed to exchange authorization code for access token'
                        });
                    }
                } catch (error) {
                    logger.error('OAuth callback error', {
                        error: error.message,
                        stack: error.stack,
                        code: req.query.code
                    });
                    res.status(500).json({
                        error: 'OAuth callback error',
                        message: 'An error occurred during OAuth callback processing'
                    });
                }
            } else if (appName === 'gitCaptain' && webServ === 'checkGitCaptainStatus') {
                res.setHeader('Content-Type', 'application/json');
                res.json({
                    "statusCode": 200,
                    "status": gitCaptainStatus,
                    "reason": gitCaptainReason,
                    "clientID": client_id,
                    "orgName": orgName,
                    "clientTimeout": clientTimeOut,
                    "gitPortEndPoint": config.web.gitPortEndPoint
                });
            } else if (req.url !== '/json' && req.url !== '/version' && req.url !== "/json/version") {
                // Check if this is an OAuth callback to authenticated.html
                if (req.url.startsWith('/authenticated.html') && req.query.code) {
                    // This is a direct OAuth callback from GitHub
                    // Just serve the file - the JavaScript will handle the token exchange
                    res.sendFile(path.join(__dirname, '..', '/public/views/authenticated.html'));
                } else {
                    res.status(404).sendFile(path.join(__dirname, '..', '/public/views/404.html'));
                }
            }
        } catch (error) {
            logger.error('GET request error', {
                error: error.message,
                stack: error.stack,
                url: req.url,
                method: req.method,
                ip: req.ip
            });
            res.status(500).json({
                error: 'Internal server error',
                message: 'An unexpected error occurred'
            });
        }
    });

app.get('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, '..', '/public/views/404.html'));
});

// Start the HTTPS server
https.createServer(credentials, app).listen(app.get('port'), () => {
    logger.info(`HTTPS server listening on port ${app.get('port')}`, {
        port: app.get('port'),
        environment: process.env.NODE_ENV || 'development'
    });
    console.log(`HTTPS server listening on port ${app.get('port')}`);
});

