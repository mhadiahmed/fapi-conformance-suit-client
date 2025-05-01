import axios from 'axios';
import { FAPIClient } from './fapiClient';
import * as https from 'https';

/**
 * This script directly executes the encrypted ID token test in a more controlled way.
 */
async function runEncryptedIdTokenTest() {
    console.log('\n========== ENCRYPTED ID TOKEN TEST ==========\n');
    
    if (process.argv.length < 4) {
        console.error('Usage: npm run encrypted-idtoken-test <discoveryUrl> <resourceEndpoint>');
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
            clientSecret: 'ae149792-aeb9-40c6-9498-5f64d65262b1',
            tokenEndpoint: 'https://mtls-www.certification.openid.net/test-mtls/a/seentarbi-ais-corporate/token',
            parEndpoint: 'https://mtls-www.certification.openid.net/test-mtls/a/seentarbi-ais-corporate/par',
            redirectUri: 'https://www.certification.openid.net/test/a/seentarbi-ais-corporate/callback',
            certPath: './src/certs/client.crt',
            keyPath: './src/certs/client.key',
            signingKeyPath: './src/certs/signin-key-Seen Tarbi for Fintech-seen-tarbee-corporate.pem',
            issuer: 'https://www.certification.openid.net/test/a/seentarbi-ais-corporate/'
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
        
        // Step 5: Make the authorization request (this should return an encrypted ID token)
        console.log('\n--- Step 5: Making authorization request ---');
        try {
            const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            console.log('Authorization response:', authResponse);
            
            if (authResponse.redirectUrl) {
                // Step 6: Process the redirect URL to get the encrypted ID token
                console.log('\n--- Step 6: Processing redirect URL ---');
                console.log('Redirect URL:', authResponse.redirectUrl);
                
                const tokenResponse = await client.handleRedirectUrlAndExchangeCode(authResponse.redirectUrl);
                console.log('Token response received, checking for ID token...');
                
                if (!tokenResponse.id_token) {
                    console.error('No ID token found in token response');
                    throw new Error('No ID token found in token response');
                }
                
                console.log('ID token received:', tokenResponse.id_token.substring(0, 20) + '...');
                
                // Step 7: Call resource endpoint with access token
                console.log('\n--- Step 7: Calling resource endpoint with access token ---');
                try {
                    const resourceResponse = await axios.get(resourceEndpoint, {
                        headers: {
                            'Authorization': `Bearer ${tokenResponse.access_token}`
                        },
                        httpsAgent
                    });
                    
                    console.log('Resource endpoint response status:', resourceResponse.status);
                    console.log('Resource endpoint response data:', resourceResponse.data);
                    
                    console.log('\n========== TEST COMPLETED SUCCESSFULLY ==========\n');
                } catch (error: any) {
                    console.error('Error calling resource endpoint:', error.message);
                    throw error;
                }
            } else {
                console.error('No redirect URL in authorization response');
                throw new Error('No redirect URL in authorization response');
            }
        } catch (error: any) {
            // If we got a redirect response with a code in the error
            if (error.response?.status === 302 || error.response?.status === 303) {
                const location = error.response.headers.location;
                if (location) {
                    console.log('Redirect URL from error response:', location);
                    
                    // Process the redirect URL to get the encrypted ID token
                    console.log('\n--- Step 6: Processing redirect URL from error response ---');
                    
                    const tokenResponse = await client.handleRedirectUrlAndExchangeCode(location);
                    console.log('Token response received, checking for ID token...');
                    
                    if (!tokenResponse.id_token) {
                        console.error('No ID token found in token response');
                        throw new Error('No ID token found in token response');
                    }
                    
                    console.log('ID token received:', tokenResponse.id_token.substring(0, 20) + '...');
                    
                    // Step 7: Call resource endpoint with access token
                    console.log('\n--- Step 7: Calling resource endpoint with access token ---');
                    try {
                        const resourceResponse = await axios.get(resourceEndpoint, {
                            headers: {
                                'Authorization': `Bearer ${tokenResponse.access_token}`
                            },
                            httpsAgent
                        });
                        
                        console.log('Resource endpoint response status:', resourceResponse.status);
                        console.log('Resource endpoint response data:', resourceResponse.data);
                        
                        console.log('\n========== TEST COMPLETED SUCCESSFULLY ==========\n');
                    } catch (error: any) {
                        console.error('Error calling resource endpoint:', error.message);
                        throw error;
                    }
                } else {
                    console.error('No redirect URL in error response');
                    throw new Error('No redirect URL in error response');
                }
            } else {
                console.error('Authorization request failed:', error.message);
                throw error;
            }
        }
    } catch (error) {
        console.error('Test failed:', error);
    }
}

// Run the test
runEncryptedIdTokenTest().catch(console.error); 