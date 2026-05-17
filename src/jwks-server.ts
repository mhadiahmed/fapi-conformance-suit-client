import express from 'express';
import { FAPIClient, FAPIClientConfig } from './fapiClient';
import * as path from 'path';
import * as https from 'https';
import * as fs from 'fs';

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 8080;
const URLSTREAM = 'https://www.certification.openid.net';
const URLSTREAM_MTLS = 'https://mtls-www.certification.openid.net';
// Get test alias from environment or use default
const TEST_ALIAS = process.env.TEST_ALIAS || 'ksa-rp';
console.log(`Using test alias: ${TEST_ALIAS}`);

// Initialize FAPI client with configuration
const config: FAPIClientConfig = {
    clientId: 'bc680915-bbd3-45d7-b3c6-2716f4d178ed',
    clientSecret: '',
    tokenEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/${TEST_ALIAS}/token`, // mTLS endpoint (uses alias)
    parEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/${TEST_ALIAS}/par`, // mTLS endpoint (uses alias)
    issuer: `${URLSTREAM}/test/a/${TEST_ALIAS}`, // Issuer uses alias
    discoveryUrl: `${URLSTREAM}/test/a/${TEST_ALIAS}/.well-known/openid-configuration`, // Discovery uses base path
    redirectUri: `${URLSTREAM}/test/a/${TEST_ALIAS}/callback`,
    certPath: path.join(__dirname, 'certs/certs.pem'),
    keyPath: path.join(__dirname, 'certs/privatekey.key'),
    signingKeyPath: path.join(__dirname, 'certs/private_key.pem'),
    keyId: 'sig1'
};

let client: FAPIClient | null = null;

// Initialize client
try {
    client = new FAPIClient(config);
    console.log('FAPI Client initialized successfully');
} catch (error) {
    console.error('Failed to initialize FAPI Client:', error);
    process.exit(1);
}

// JWKS endpoint
app.get('/jwks', (req, res): void => {
    if (!client) {
        res.status(500).json({ error: 'Client not initialized' });
        return;
    }
    
    try {
        const jwk = client.getJwks();
        const jwks = {
            keys: [jwk]
        };
        
        res.setHeader('Content-Type', 'application/json');
        res.json(jwks);
    } catch (error) {
        console.error('Error generating JWKS:', error);
        res.status(500).json({ error: 'Failed to generate JWKS' });
    }
});

// Bank-scoped JWKS endpoint (for compatibility)
app.get('/jwks/:bankCode', (req, res): void => {
    if (!client) {
        res.status(500).json({ error: 'Client not initialized' });
        return;
    }
    
    try {
        const jwk = client.getJwks();
        const jwks = {
            keys: [jwk]
        };
        
        res.setHeader('Content-Type', 'application/json');
        res.json(jwks);
    } catch (error) {
        console.error('Error generating JWKS:', error);
        res.status(500).json({ error: 'Failed to generate JWKS' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', clientInitialized: client !== null });
});

// Trigger endpoint to start authorization flow
app.post('/trigger-flow', async (req, res) => {
    if (!client) {
        res.status(500).json({ error: 'Client not initialized' });
        return;
    }

    try {
        console.log('\n========== STARTING AUTHORIZATION FLOW ==========');
        
        // Set requested scopes
        client.setRequestedScopes(['openid', 'accounts']);

        // Create HTTPS agent with mTLS certificates
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(config.certPath!),
            key: fs.readFileSync(config.keyPath!),
            rejectUnauthorized: false // For test environment only
        });

        // Step 1: Create request object for PAR
        console.log('Creating request object...');
        const requestObject = await client.createRequestObject();
        
        if (!requestObject) {
            throw new Error('Failed to create request object. Check signing key configuration.');
        }
        
        console.log('Submitting PAR request...');
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        if (!parResponse.request_uri) {
            throw new Error('No request_uri received from PAR endpoint');
        }

        // Step 2: Get authorization URL with client_id
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('\n=== Authorization URL ===');
        console.log(authUrl);
        console.log('========================\n');

        // Return the authorization URL so it can be opened in a browser
        res.json({
            success: true,
            authorizationUrl: authUrl,
            message: 'Open this URL in your browser to complete authorization'
        });

    } catch (error: any) {
        console.error('Error triggering flow:', error);
        res.status(500).json({ 
            error: 'Failed to trigger authorization flow',
            details: error.message 
        });
    }
});

// Callback endpoint to handle authorization response
app.get('/callback', async (req, res) => {
    if (!client) {
        res.status(500).send('Client not initialized');
        return;
    }

    try {
        console.log('\n========== AUTHORIZATION CALLBACK RECEIVED ==========');
        console.log('Query params:', req.query);

        // The full callback URL
        const callbackUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
        console.log('Full callback URL:', callbackUrl);

        // Handle the redirect URL and exchange code for tokens
        console.log('Processing redirect and exchanging code for tokens...');
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(callbackUrl);
        
        console.log('Token exchange successful!');
        console.log('Access token received');
        if (tokenResponse.refresh_token) {
            console.log('Refresh token received');
        }

        res.send(`
            <html>
                <body>
                    <h1>Authorization Successful!</h1>
                    <p>The authorization flow completed successfully.</p>
                    <p>Access Token: ${tokenResponse.access_token ? 'Received' : 'Not received'}</p>
                    <p>Refresh Token: ${tokenResponse.refresh_token ? 'Received' : 'Not received'}</p>
                    <p>You can close this window and check the server logs for details.</p>
                </body>
            </html>
        `);

    } catch (error: any) {
        console.error('Error in callback:', error);
        res.status(500).send(`
            <html>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>Error: ${error.message}</p>
                    <pre>${error.stack}</pre>
                </body>
            </html>
        `);
    }
});

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`FAPI Client Server running on http://localhost:${PORT}`);
    console.log(`Test Alias: ${TEST_ALIAS}`);
    console.log(`========================================`);
    console.log(`Endpoints:`);
    console.log(`  - JWKS: http://localhost:${PORT}/jwks`);
    console.log(`  - Health: http://localhost:${PORT}/health`);
    console.log(`  - Trigger Flow: POST http://localhost:${PORT}/trigger-flow`);
    console.log(`  - Callback: http://localhost:${PORT}/callback`);
    console.log(`========================================\n`);
});

