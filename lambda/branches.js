/**
 * Branch Operations Lambda Handler
 * Handles: searchForRepos, createBranches, searchForBranch, searchForPR, logOff, deleteBranch
 */

const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const axios = require('axios');

const secretsClient = new SecretsManagerClient({ region: process.env.AWS_REGION });

const gitHubAPIendpoint = 'https://api.github.com';
const gitHubEndPoint = 'https://github.com';
const orgName = process.env.GITHUB_ORG_NAME || '';

let cachedSecrets = null;

async function getSecrets() {
    if (cachedSecrets) {
        return cachedSecrets;
    }

    try {
        const response = await secretsClient.send(
            new GetSecretValueCommand({
                SecretId: process.env.SECRETS_ARN
            })
        );

        cachedSecrets = JSON.parse(response.SecretString);
        return cachedSecrets;
    } catch (error) {
        console.error('Error retrieving secrets:', error);
        throw new Error('Failed to retrieve OAuth credentials');
    }
}

async function makeGitHubRequest(options, token) {
    const headers = {
        'User-Agent': 'Git-Captain',
        'Authorization': `token ${token}`,
        'Accept': 'application/json',
        ...options.headers
    };

    try {
        const response = await axios({
            method: options.method || 'GET',
            url: options.url,
            data: options.body,
            headers: headers,
            auth: options.auth,
            validateStatus: () => true // Don't throw on any status
        });

        return {
            statusCode: response.status,
            body: JSON.stringify(response.data)
        };
    } catch (error) {
        console.error('GitHub request error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message })
        };
    }
}

function createResponse(statusCode, body) {
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        body: typeof body === 'string' ? body : JSON.stringify(body)
    };
}

exports.handler = async (event) => {
    console.log('Branch operations event:', JSON.stringify(event, null, 2));

    const pathParams = event.pathParameters || {};
    const { appName, webServ } = pathParams;
    const method = event.httpMethod;

    let body = {};
    if (event.body) {
        try {
            body = JSON.parse(event.body);
        } catch (e) {
            console.error('Failed to parse body:', e);
        }
    }

    try {
        // Handle OAuth token exchange (POST to getToken)
        if (appName === 'gitCaptain' && webServ === 'getToken' && method === 'POST') {
            const authCode = event.queryStringParameters?.code;
            
            if (!authCode) {
                return createResponse(400, {
                    error: 'Missing authorization code',
                    message: 'OAuth authorization code is required'
                });
            }

            const secrets = await getSecrets();
            const { client_id, client_secret } = secrets;

            const tokenUrl = `${gitHubEndPoint}/login/oauth/access_token?client_id=${client_id}&client_secret=${client_secret}&code=${authCode}&scope=repo`;

            const response = await axios.post(tokenUrl, {}, {
                headers: {
                    'User-Agent': 'Git-Captain',
                    'Accept': 'application/x-www-form-urlencoded'
                }
            });

            if (response.status === 200) {
                return createResponse(200, {
                    statusCode: 200,
                    body: response.data
                });
            } else {
                return createResponse(response.status, {
                    error: 'OAuth token exchange failed',
                    message: 'Failed to exchange authorization code for access token'
                });
            }
        }

        // Handle repository search
        if (appName === 'gitCaptain' && webServ === 'searchForRepos' && method === 'POST') {
            if (!body.token) {
                return createResponse(400, { error: 'Token is required' });
            }

            const urlForRepoSearch = `${gitHubAPIendpoint}/user/repos`;
            const options = {
                method: 'GET',
                url: urlForRepoSearch
            };

            const repoResponse = await makeGitHubRequest(options, body.token);
            return createResponse(200, {
                statusCode: repoResponse.statusCode,
                body: repoResponse.body
            });
        }

        // Handle branch creation
        if (appName === 'gitCaptain' && webServ === 'createBranches' && method === 'POST') {
            if (!body.token || !body.repo || !body.branchRef || !body.newBranch) {
                return createResponse(400, { 
                    error: 'Missing required fields',
                    message: 'token, repo, branchRef, and newBranch are required'
                });
            }

            const urlForCreate = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/git/refs/heads/${body.branchRef}`;
            const options = {
                method: 'GET',
                url: urlForCreate
            };

            let refResponse = await makeGitHubRequest(options, body.token);

            // Try default branches if specified branch not found
            if (refResponse.statusCode === 404) {
                const defaultBranches = ['main', 'master', 'develop'];
                
                for (const defaultBranch of defaultBranches) {
                    if (defaultBranch !== body.branchRef) {
                        const defaultUrl = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/git/refs/heads/${defaultBranch}`;
                        const defaultOptions = {
                            method: 'GET',
                            url: defaultUrl
                        };
                        
                        refResponse = await makeGitHubRequest(defaultOptions, body.token);
                        
                        if (refResponse.statusCode === 200) {
                            break;
                        }
                    }
                }
            }

            if (refResponse.statusCode === 200) {
                const myJSONobjRef = JSON.parse(refResponse.body);
                const urlForBranches = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/git/refs`;

                const branchOptions = {
                    method: 'POST',
                    url: urlForBranches,
                    body: {
                        ref: `refs/heads/${body.newBranch}`,
                        sha: myJSONobjRef.object.sha
                    }
                };

                const branchResponse = await makeGitHubRequest(branchOptions, body.token);
                
                return createResponse(200, {
                    statusCode: branchResponse.statusCode,
                    body: branchResponse.body
                });
            } else {
                return createResponse(200, {
                    statusCode: refResponse.statusCode,
                    message: `Could not find branch '${body.branchRef}' or any default branches in repository '${body.repo}'`
                });
            }
        }

        // Handle branch search
        if (appName === 'gitCaptain' && webServ === 'searchForBranch' && method === 'POST') {
            if (!body.token || !body.repo || !body.searchForBranch) {
                return createResponse(400, { 
                    error: 'Missing required fields',
                    message: 'token, repo, and searchForBranch are required'
                });
            }

            const urlForSearch = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/git/refs/heads/${body.searchForBranch}`;
            const options = {
                method: 'GET',
                url: urlForSearch
            };

            const searchResponse = await makeGitHubRequest(options, body.token);
            return createResponse(200, {
                statusCode: searchResponse.statusCode,
                body: searchResponse.body
            });
        }

        // Handle PR search
        if (appName === 'gitCaptain' && webServ === 'searchForPR' && method === 'POST') {
            if (!body.token || !body.repo || !body.state || !body.prBaseBranch) {
                return createResponse(400, { 
                    error: 'Missing required fields',
                    message: 'token, repo, state, and prBaseBranch are required'
                });
            }

            const urlForPRsearch = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/pulls?state=${body.state}&base=${body.prBaseBranch}`;
            const options = {
                method: 'GET',
                url: urlForPRsearch
            };

            const prResponse = await makeGitHubRequest(options, body.token);
            return createResponse(200, {
                statusCode: prResponse.statusCode,
                body: prResponse.body
            });
        }

        // Handle logout/token revocation
        if (appName === 'gitCaptain' && webServ === 'logOff' && method === 'POST') {
            if (!body.token) {
                return createResponse(400, { error: 'Token is required' });
            }

            const secrets = await getSecrets();
            const { client_id, client_secret } = secrets;

            const urlForRevokeToken = `${gitHubAPIendpoint}/applications/${client_id}/tokens/${body.token}`;
            const options = {
                method: 'DELETE',
                url: urlForRevokeToken,
                auth: {
                    username: client_id,
                    password: client_secret
                }
            };

            const logoffResponse = await makeGitHubRequest(options, body.token);
            return createResponse(logoffResponse.statusCode, logoffResponse.body);
        }

        // Handle branch deletion
        if (method === 'DELETE') {
            if (!body.token || !body.repo || !body.deleteBranch) {
                return createResponse(400, { 
                    error: 'Missing required fields',
                    message: 'token, repo, and deleteBranch are required'
                });
            }

            const urlForDelete = `${gitHubAPIendpoint}/repos/${orgName}/${body.repo}/git/refs/heads/${body.deleteBranch}`;
            const options = {
                method: 'DELETE',
                url: urlForDelete
            };

            const deleteResponse = await makeGitHubRequest(options, body.token);
            return createResponse(200, {
                statusCode: deleteResponse.statusCode,
                body: deleteResponse.body
            });
        }

        // No matching endpoint
        return createResponse(404, {
            error: 'Endpoint not found',
            message: 'The requested endpoint does not exist',
            appName,
            webServ,
            method
        });

    } catch (error) {
        console.error('Branch operations error:', error);
        return createResponse(500, {
            error: 'Internal server error',
            message: error.message
        });
    }
};
