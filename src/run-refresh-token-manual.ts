import * as readline from 'readline';
import { FAPIClient } from './fapiClient';
import * as https from 'https';

/**
 * This script provides a step-by-step guide to manually test the refresh token flow.
 * It will provide instructions at each step for what needs to be done manually.
 */
const URLSTREAM = 'https://www.certification.openid.net';
const URLSTREAM_MTLS = 'https://mtls-www.certification.openid.net';
async function runManualRefreshTokenTest() {
    console.log('\n========== MANUAL REFRESH TOKEN FLOW TEST ==========\n');
    
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const askQuestion = (question: string): Promise<string> => {
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                resolve(answer);
            });
        });
    };

    try {
        // Step 1: Initialize client
        console.log('Step 1: Initializing client...\n');
        const client = new FAPIClient({
            clientId: '2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
            clientSecret: 'secret-2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
            tokenEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/seentarbi-ais-corporate/token`,
            parEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/seentarbi-ais-corporate/par`,
            redirectUri: `${URLSTREAM}/test/a/seentarbi-ais-corporate/callback`,
            certPath: './src/certs/client.crt',
            keyPath: './src/certs/client.key',
            signingKeyPath: './src/certs/signin-key-Seen Tarbi for Fintech-seen-tarbee-corporate.pem',
            issuer: `${URLSTREAM}/test/a/seentarbi-ais-corporate/`
        });
        
        await client.initialize();
        console.log('Client initialized successfully.\n');
        
        // Step 2: Explain the test flow
        console.log('Step 2: Test Overview\n');
        console.log('This test will verify the refresh token flow following these steps:');
        console.log('1. Create an account consent');
        console.log('2. Get an authorization code via PAR (Pushed Authorization Request)');
        console.log('3. Exchange the authorization code for tokens');
        console.log('4. Call a resource endpoint (which will return 401)');
        console.log('5. Use refresh token to get a new access token (twice)');
        console.log('6. Call the resource endpoint again with the new access token\n');
        
        await askQuestion('Press Enter to continue...');
        
        // Step 3: Create account consent
        console.log('\nStep 3: Creating account consent...\n');
        client.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Account consent created with ID:', accountConsentRequest.Data.ConsentId);
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        
        // Step 4: Create and submit PAR
        console.log('\nStep 4: Creating and submitting PAR...\n');
        const requestObject = await client.createRequestObject();
        if (!requestObject) {
            throw new Error('Failed to create request object');
        }
        
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR response request_uri:', parResponse.request_uri);
        
        // Step 5: Get authorization URL
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('\nStep 5: Manual Authorization\n');
        console.log('Please take the following authorization URL and:');
        console.log('1. Open it in a web browser');
        console.log('2. Complete the authorization process');
        console.log('3. When redirected, copy the full redirect URL (including any fragments after #)\n');
        console.log('Authorization URL:');
        console.log(authUrl);
        
        // Attempt to execute the authorization request automatically
        console.log('\nAttempting to execute the authorization request...');
        try {
            // Create an HTTPS agent that ignores SSL validation errors
            const httpsAgent = new https.Agent({
                rejectUnauthorized: false
            });
            
            // Try using the client's makeAuthorizationRequest method which handles mTLS
            console.log('Using client.makeAuthorizationRequest for proper mTLS...');
            try {
                const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
                if (authResponse.redirectUrl) {
                    console.log('\nReceived redirect to:', authResponse.redirectUrl);
                    console.log('You can use this redirect URL for the next step.');
                }
            } catch (error: any) {
                // This might be expected if the response is a redirect (303)
                if (error.response?.status === 303 && error.response?.headers?.location) {
                    console.log('\nReceived 303 redirect to:', error.response.headers.location);
                    console.log('You can use this redirect URL for the next step.');
                } else {
                    console.log('Could not use client.makeAuthorizationRequest:', error.message);
                    
                    // Fall back to regular fetch
                    console.log('Falling back to regular fetch...');
                    const authResponse = await fetch(authUrl, {
                        method: 'GET',
                        redirect: 'manual', // Don't automatically follow redirects
                        // @ts-ignore
                        agent: httpsAgent
                    });
                    
                    if (authResponse.status === 302 || authResponse.status === 303) {
                        const location = authResponse.headers.get('location');
                        console.log('\nReceived redirect to:', location);
                        console.log('You can use this redirect URL for the next step or continue with the browser flow.');
                    } else {
                        console.log('Received response with status:', authResponse.status);
                        console.log('Please continue with the browser flow to get the redirect URL.');
                    }
                }
            }
        } catch (error) {
            console.log('Could not automatically execute authorization request:', error);
            console.log('Please continue with the browser flow to get the redirect URL.');
        }
        
        console.log('\n');
        
        const redirectUrl = await askQuestion('Paste the complete redirect URL here: ');
        if (!redirectUrl || !redirectUrl.includes('callback')) {
            throw new Error('Invalid redirect URL provided');
        }
        
        // Step 6: Process the redirect URL and exchange code for token
        console.log('\nStep 6: Processing redirect URL and exchanging code for token...\n');
        console.log('Redirect URL:', redirectUrl);
        
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token exchange successful!');
        console.log('Access token:', tokenResponse.access_token.substring(0, 15) + '...');
        console.log('Refresh token:', tokenResponse.refresh_token.substring(0, 15) + '...');
        
        // Step 7: Ask for resource endpoint
        console.log('\nStep 7: Calling resource endpoint\n');
        const resourceEndpoint = await askQuestion('Enter the resource endpoint URL (e.g., https://https://mtls-www.certification.openid.net/test-mtls/a/seentarbi-ais-corporate/accounts/payments/resources): ');
        
        // Create an HTTPS agent with the correct client certificates
        const fs = require('fs');
        const mtlsAgent = new https.Agent({
            cert: fs.readFileSync('./src/certs/client.crt'),
            key: fs.readFileSync('./src/certs/client.key'),
            rejectUnauthorized: false // Only for testing environments
        });
        
        console.log('Calling resource endpoint with access token...');
        try {
            // Make the resource request with proper mTLS
            const response = await fetch(resourceEndpoint, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${tokenResponse.access_token}`
                },
                // @ts-ignore - TypeScript doesn't know about agent property
                agent: mtlsAgent
            });
            
            if (response.status === 401) {
                console.log('Got expected 401 Unauthorized response from resource endpoint.');
                
                // Step 8: First refresh token call
                console.log('\nStep 8: Performing first refresh token call...\n');
                const firstRefreshResponse = await client.refreshAccessToken(tokenResponse.refresh_token);
                console.log('First refresh successful!');
                console.log('New access token:', firstRefreshResponse.access_token.substring(0, 15) + '...');
                console.log('New refresh token:', firstRefreshResponse.refresh_token.substring(0, 15) + '...');
                
                // Step 9: Second refresh token call
                console.log('\nStep 9: Performing second refresh token call...\n');
                const secondRefreshResponse = await client.refreshAccessToken(firstRefreshResponse.refresh_token);
                console.log('Second refresh successful!');
                console.log('Final access token:', secondRefreshResponse.access_token.substring(0, 15) + '...');
                
                // Step 10: Retry resource endpoint with new access token
                console.log('\nStep 10: Retrying resource endpoint with new access token...\n');
                const retryResponse = await fetch(resourceEndpoint, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${secondRefreshResponse.access_token}`
                    },
                    // @ts-ignore - TypeScript doesn't know about agent property
                    agent: mtlsAgent
                });
                
                const responseText = await retryResponse.text();
                console.log('Resource endpoint response status:', retryResponse.status);
                console.log('Resource endpoint response:', responseText);
                
                console.log('\n========== TEST COMPLETED SUCCESSFULLY ==========\n');
            } else {
                console.log('Unexpected response from resource endpoint.');
                console.log('Status:', response.status);
                console.log('Response:', await response.text());
            }
        } catch (error) {
            console.error('Error calling resource endpoint:', error);
        }
    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        rl.close();
    }
}

// Run the test
runManualRefreshTokenTest().catch(console.error); 