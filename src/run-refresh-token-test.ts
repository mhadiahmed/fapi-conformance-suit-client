import axios from 'axios';
import { FAPIClient } from './fapiClient';
import * as crypto from 'crypto';
import * as https from 'https';

/**
 * This script directly executes the refresh token flow test in a more controlled way.
 */
async function runRefreshTokenFlowTest() {
    console.log('\n========== REFRESH TOKEN FLOW TEST ==========\n');
    
    if (process.argv.length < 4) {
        console.error('Usage: npm run refresh-token-test <discoveryUrl> <resourceEndpoint>');
        process.exit(1);
    }
    
    const discoveryUrl = process.argv[2];
    const resourceEndpoint = process.argv[3];
    
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    // Create HTTPS agent to ignore SSL certificate validation for testing
    const httpsAgent = new https.Agent({
        rejectUnauthorized: false // Only for testing environments
    });
    
    try {
        // Initialize client
        const client = new FAPIClient({
            clientId: '2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
            clientSecret: 'secret-2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
            tokenEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/seentarbi-ais-corporate/token',
            parEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/seentarbi-ais-corporate/par',
            redirectUri: 'https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate/callback',
            certPath: './src/certs/client.crt',
            keyPath: './src/certs/client.key',
            signingKeyPath: './src/certs/signin-key-Seen Tarbi for Fintech-seen-tarbee-corporate.pem',
            // caCertPath: './src/certs/ca.pem',
            issuer: 'https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate/'
        });
        
        await client.initialize();
        console.log('Client initialized successfully.');
        
        // Step 1: Get OpenID configuration
        console.log('\n--- Step 1: Fetching OpenID configuration ---');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        
        // Step 2: Create account consent
        console.log('\n--- Step 2: Creating account consent ---');
        client.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Consent ID:', accountConsentRequest.Data.ConsentId);
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        
        // Step 3: Create and submit PAR
        console.log('\n--- Step 3: Creating and submitting PAR ---');
        const requestObject = await client.createRequestObject();
        if (!requestObject) {
            throw new Error('Failed to create request object');
        }
        
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR response request_uri:', parResponse.request_uri);
        
        // Step 4: Get authorization URL
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('\n--- Step 4: Authorization URL ---');
        console.log(authUrl);
        
        // Step 5: Manual step - Get the authorization code
        console.log('\n--- Step 5: MANUAL ACTION REQUIRED ---');
        console.log('Open the authorization URL in a browser, authorize the request, and copy the redirect URL.');
        console.log('Paste the complete redirect URL below and press Enter:');
        
        // For testing, use a predefined redirect URL
        // In a real scenario, you would read from stdin or have a callback endpoint
        const redirectUrl = await getRedirectUrlFromUser();
        
        // Step 6: Process the redirect URL and exchange code for token
        console.log('\n--- Step 6: Processing redirect URL ---');
        console.log('Redirect URL:', redirectUrl);
        
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Access token received:', tokenResponse.access_token.substring(0, 10) + '...');
        console.log('Refresh token received:', tokenResponse.refresh_token.substring(0, 10) + '...');
        
        // Step 7: Call resource endpoint with access token (expected to get 401)
        console.log('\n--- Step 7: Calling resource endpoint ---');
        try {
            const resourceResponse = await axios.get(resourceEndpoint, {
                headers: {
                    'Authorization': `Bearer ${tokenResponse.access_token}`
                },
                httpsAgent // Add the HTTPS agent to ignore SSL validation
            });
            console.log('Unexpected success. Expected 401 but got:', resourceResponse.status);
        } catch (error: any) {
            if (error.response?.status === 401) {
                console.log('Got expected 401 response from resource endpoint.');
                
                // Step 8: First refresh token call
                console.log('\n--- Step 8: First refresh token call ---');
                const firstRefreshResponse = await client.refreshAccessToken(tokenResponse.refresh_token);
                console.log('New access token:', firstRefreshResponse.access_token.substring(0, 10) + '...');
                console.log('New refresh token:', firstRefreshResponse.refresh_token.substring(0, 10) + '...');
                
                // Step 9: Second refresh token call
                console.log('\n--- Step 9: Second refresh token call ---');
                const secondRefreshResponse = await client.refreshAccessToken(firstRefreshResponse.refresh_token);
                console.log('Final access token:', secondRefreshResponse.access_token.substring(0, 10) + '...');
                
                // Step 10: Retry resource endpoint with new access token
                console.log('\n--- Step 10: Retrying resource endpoint with new access token ---');
                const retryResponse = await axios.get(resourceEndpoint, {
                    headers: {
                        'Authorization': `Bearer ${secondRefreshResponse.access_token}`
                    },
                    httpsAgent // Add the HTTPS agent to ignore SSL validation
                });
                console.log('Resource endpoint response status:', retryResponse.status);
                console.log('Resource endpoint response data:', retryResponse.data);
                
                console.log('\n========== TEST COMPLETED SUCCESSFULLY ==========\n');
            } else {
                console.error('Unexpected error calling resource endpoint:', error.message);
                throw error;
            }
        }
    } catch (error) {
        console.error('Test failed:', error);
    }
}

// Function to simulate getting a redirect URL from the user
// In a real scenario, you would read from stdin or have a callback endpoint
async function getRedirectUrlFromUser(): Promise<string> {
    // For testing, just return a mock redirect URL
    // You can implement a real input mechanism here
    
    console.log('Enter redirect URL (or press Enter to use example URL):');
    
    return new Promise<string>((resolve) => {
        // Wait for user input on stdin
        process.stdin.once('data', (data) => {
            const input = data.toString().trim();
            if (input) {
                resolve(input);
            } else {
                // If user just pressed Enter, use a test URL
                console.log('Using example redirect URL...');
                resolve('https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate/callback#state=1234567890&code=AbCdEfGhIjKlMnOpQrStUvWxYz&id_token=eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyLXRlc3QiLCJhdWQiOiIyZDRjOTVhNy02ZGMzLTQ0MTYtYWIxYy1lYTQ0NTAxNjM1YWEifQ.signature');
            }
        });
    });
}

// Run the test
runRefreshTokenFlowTest().catch(console.error);
