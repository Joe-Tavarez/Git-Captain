/**
 * GitHub OAuth Lambda Handler
 */

const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const axios = require('axios');

const secretsClient = new SecretsManagerClient({ region: process.env.AWS_REGION });

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

exports.handler = async (event) => {
    console.log('OAuth event:', JSON.stringify(event, null, 2));

    try {
        const authCode = event.queryStringParameters?.code;
        
        if (!authCode) {
            return {
                statusCode: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'Missing authorization code',
                    message: 'OAuth authorization code is required'
                })
            };
        }

        const secrets = await getSecrets();
        const { client_id, client_secret } = secrets;

        const tokenUrl = `https://github.com/login/oauth/access_token?client_id=${client_id}&client_secret=${client_secret}&code=${authCode}&scope=repo`;

        const response = await axios.post(tokenUrl, {}, {
            headers: {
                'User-Agent': 'Git-Captain',
                'Accept': 'application/json'
            }
        });

        if (response.status === 200 && response.data.access_token) {
            // Get the CloudFront domain or API Gateway domain
            const baseUrl = event.headers['CloudFront-Forwarded-Proto'] 
                ? `https://${event.headers.Host}` 
                : `https://${event.requestContext.domainName}/${event.requestContext.stage}`;

            return {
                statusCode: 302,
                headers: {
                    'Location': `/views/authenticated.html?code=${authCode}`,
                    'Access-Control-Allow-Origin': '*'
                },
                body: ''
            };
        } else {
            console.error('OAuth token exchange failed:', response.data);
            return {
                statusCode: response.status || 500,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    error: 'OAuth token exchange failed',
                    message: 'Failed to exchange authorization code for access token'
                })
            };
        }
    } catch (error) {
        console.error('OAuth callback error:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                error: 'OAuth callback error',
                message: error.message
            })
        };
    }
};
