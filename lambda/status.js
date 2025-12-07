/**
 * Status Check Lambda Handler
 */

const axios = require('axios');

exports.handler = async (event) => {
    console.log('Status event:', JSON.stringify(event, null, 2));

    const pathParams = event.pathParameters || {};
    const { appName, webServ } = pathParams;

    try {
        if (appName === 'gitCaptain' && webServ === 'checkGitHubStatus') {
            // Check GitHub API status
            const response = await axios.get('https://status.github.com/api/last-message.json', {
                headers: {
                    'User-Agent': 'Git-Captain'
                }
            });

            return {
                statusCode: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify(response.data)
            };
        } else if (appName === 'gitCaptain' && webServ === 'checkGitCaptainStatus') {
            // Return Git-Captain status
            const status = {
                statusCode: 200,
                status: process.env.GIT_CAPTAIN_STATUS || 'up',
                reason: process.env.GIT_CAPTAIN_REASON || 'Service is operational',
                clientID: process.env.GITHUB_CLIENT_ID || '',
                orgName: process.env.GITHUB_ORG_NAME || '',
                clientTimeout: process.env.TIMEOUT_MINUTES || '25',
                gitPortEndPoint: `https://${event.requestContext.domainName}/${event.requestContext.stage}`,
                serverless: true
            };

            return {
                statusCode: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify(status)
            };
        }

        return {
            statusCode: 404,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({ error: 'Endpoint not found' })
        };
    } catch (error) {
        console.error('Status check error:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'Internal server error',
                message: error.message
            })
        };
    }
};
