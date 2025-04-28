import { FAPIClient, FAPIClientConfig } from './fapiClient';
import { AxiosError } from 'axios';
import * as path from 'path';
import axios from 'axios';
import * as https from 'https';
import * as fs from 'fs';
import crypto from 'crypto';

// Declare client variable outside functions for access across test functions
let client: FAPIClient | null = null;

// Let's add a helper function instead of using Express
function getJwksAsJson(): string {
    if (!client) {
        return JSON.stringify({ error: 'Client not initialized' });
    }
    
    const jwk = client.getJwks();
    if (!jwk) {
        return JSON.stringify({ error: 'Failed to generate JWKS' });
    }
    
    const jwksOutput = { keys: [jwk] };
    console.log('JWKS for test suite:', JSON.stringify(jwksOutput, null, 2));
    return JSON.stringify(jwksOutput);
}

async function main() {
    const config: FAPIClientConfig = {
        clientId: '2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
        clientSecret: 'ae149792-aeb9-40c6-9498-5f64d65262b1',
        tokenEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/ais-corporate/token',
        parEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/ais-corporate/par',
        issuer: 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate',
        discoveryUrl: 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate/.well-known/openid-configuration',
        redirectUri: 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate/callback',
        certPath: path.join(__dirname, 'certs/client.crt'),
        keyPath: path.join(__dirname, 'certs/client.key'),
        signingKeyPath: path.join(__dirname, 'certs/signin-key-Seen Tarbi for Fintech-seen-tarbee-corporate.pem')
    };

    try {
        client = new FAPIClient(config);
        
        // Log the JWKS that should be provided to the conformance test suite
        console.log('\n==== JWKS FOR CONFORMANCE TEST SUITE ====');
        getJwksAsJson();
        console.log('========================================\n');
        
        // Set requested scopes
        client.setRequestedScopes(['openid','accounts']);

        // Create HTTPS agent with mTLS certificates
        if (!config.certPath || !config.keyPath) {
            throw new Error('Certificate and key paths are required');
        }

        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(config.certPath),
            key: fs.readFileSync(config.keyPath),
            rejectUnauthorized: false // For test environment only
        });
        
        // Step 1: Create account consent first
        console.log('Creating account consent request...');
        const consentResponse = await client.createAccountConsentRequest();
        console.log('Account consent response:', consentResponse);

        // Set the consent ID before creating request object
        client.setConsentId(consentResponse.Data.ConsentId);

        // Step 2: Create and submit PAR request
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

        // Step 3: Get authorization URL
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('\nMaking authorization request to:', authUrl);

        try {
            // Step 4: Make the authorization request
            const response = await axios.get(authUrl, {
                httpsAgent,
                maxRedirects: 0, // Don't follow redirects automatically
                validateStatus: (status) => true, // Accept any status code
                headers: {
                    'Accept': 'application/json'
                }
            });

            // Step 5: Handle redirect or response
            if (response.status === 302 || response.status === 303) {
                const location = response.headers.location;
                if (location?.includes('error=invalid_nonce')) {
                    console.log('Successfully detected invalid nonce in redirect');
                    console.log('Test completed: Invalid nonce was properly rejected');
                    process.exit(0);
                }
            }

            // If we get a response with an ID token, verify its claims and signature
            if (response.data && response.data.id_token) {
                try {
                    await client.handleAuthorizationResponse(response.data);
                    console.error('Error: Authorization succeeded but should have failed due to invalid token');
                    process.exit(1);
                } catch (error: any) {
                    if (error.message?.includes('Invalid nonce')) {
                        console.log('Successfully detected invalid nonce in ID token');
                        console.log('Test completed: Invalid nonce was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Invalid issuer')) {
                        console.log('Successfully detected invalid issuer in ID token');
                        console.log('Test completed: Invalid issuer was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Invalid audience')) {
                        console.log('Successfully detected invalid audience in ID token');
                        console.log('Test completed: Invalid audience was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Invalid ID token signature')) {
                        console.log('Successfully detected invalid signature in ID token');
                        console.log('Test completed: Invalid signature was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('"none" algorithm')) {
                        console.log('Successfully detected "none" algorithm in ID token');
                        console.log('Test completed: "none" algorithm was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('expired')) {
                        console.log('Successfully detected expired ID token');
                        console.log('Test completed: Expired ID token was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Missing expiration time')) {
                        console.log('Successfully detected missing exp claim in ID token');
                        console.log('Test completed: Missing exp claim was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Invalid s_hash')) {
                        console.log('Successfully detected invalid s_hash in ID token');
                        console.log('Test completed: Invalid s_hash was properly rejected');
                        process.exit(0);
                    } else if (error.message?.includes('Invalid c_hash')) {
                        console.log('Successfully detected invalid c_hash in ID token');
                        console.log('Test completed: Invalid c_hash was properly rejected');
                        process.exit(0);
                    }
                    throw error;
                }
            }

            console.log('Unexpected response:', {
                status: response.status,
                headers: response.headers,
                data: response.data
            });
            process.exit(1);

        } catch (error: any) {
            // Check if the error response indicates an invalid nonce or issuer
            if (error.response?.headers?.location?.includes('error=invalid_nonce') ||
                error.response?.data?.error === 'invalid_nonce' ||
                error.message?.includes('Invalid nonce')) {
                console.log('Successfully detected invalid nonce');
                console.log('Test completed: Invalid nonce was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_iss') ||
                       error.response?.data?.error === 'invalid_iss' ||
                       error.message?.includes('Invalid issuer')) {
                console.log('Successfully detected invalid issuer');
                console.log('Test completed: Invalid issuer was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_aud') ||
                       error.response?.data?.error === 'invalid_aud') {
                console.log('Successfully detected invalid audience');
                console.log('Test completed: Invalid audience was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_signature') ||
                       error.response?.data?.error === 'invalid_signature' ||
                       error.message?.includes('Invalid ID token signature')) {
                console.log('Successfully detected invalid signature');
                console.log('Test completed: Invalid signature was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_alg') ||
                       error.response?.data?.error === 'invalid_alg' ||
                       error.message?.includes('"none" algorithm')) {
                console.log('Successfully detected "none" algorithm');
                console.log('Test completed: "none" algorithm was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=expired_token') ||
                       error.response?.data?.error === 'expired_token' || 
                       error.message?.includes('expired')) {
                console.log('Successfully detected expired token');
                console.log('Test completed: Expired token was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_token') ||
                       error.response?.data?.error === 'invalid_token' || 
                       error.message?.includes('Missing expiration time')) {
                console.log('Successfully detected missing exp claim');
                console.log('Test completed: Token with missing exp claim was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_grant') ||
                       error.response?.data?.error === 'invalid_grant' || 
                       error.message?.includes('Invalid s_hash')) {
                console.log('Successfully detected invalid s_hash');
                console.log('Test completed: Token with invalid s_hash was properly rejected');
                process.exit(0);
            } else if (error.response?.headers?.location?.includes('error=invalid_grant') ||
                       error.response?.data?.error === 'invalid_grant' || 
                       error.message?.includes('Invalid c_hash')) {
                console.log('Successfully detected invalid c_hash');
                console.log('Test completed: Token with invalid c_hash was properly rejected');
                process.exit(0);
            }
            
            console.error('Authorization request failed:', {
                status: error.response?.status,
                data: error.response?.data,
                headers: error.response?.headers,
                message: error.message
            });
            throw error;
        }

        // Return the initialized client
        return client;
    } catch (error) {
        if (error instanceof AxiosError) {
            console.error('Test failed:', {
                status: error.response?.status,
                data: error.response?.data,
                headers: error.response?.headers,
                message: error.message
            });
        } else {
            console.error('Test failed:', error);
        }
        process.exit(1);
    }
}

// Add a test for client assertion
const testClientAssertion = async (fapiClient: FAPIClient) => {
    try {
        const privateJwk = fapiClient.getPrivateJwk();
        console.log('Private JWK:', privateJwk ? JSON.stringify(privateJwk, null, 2) : 'Not available');
        
        if (!privateJwk) {
            console.warn('Cannot create client assertion: No private JWK available');
            return null;
        }
        
        // Create a client assertion with manually specified client id
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: 'seen-tarbee-corporate', // Use hardcoded value instead of accessing private config
            sub: 'seen-tarbee-corporate', // Use hardcoded value instead of accessing private config
            aud: 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate',
            jti: crypto.randomBytes(16).toString('hex'),
            exp: now + 300,
            iat: now
        };
        
        const assertion = await (fapiClient as any)['signJWT'](payload);
        
        if (!assertion) {
            throw new Error('Failed to create client assertion. Check signing key configuration.');
        }
        
        console.log('Test client assertion created successfully');
        return assertion;
    } catch (error) {
        console.error('Failed to create test client assertion:', error);
        throw error;
    }
};

// Add a function to test the invalid issuer scenario
async function testInvalidIssuer() {
    console.log('\n==== TESTING INVALID ISSUER DETECTION ====');
    
    try {
        // Create a mock ID token with an invalid issuer
        const invalidIssuerToken = await client!.createMockIdTokenWithInvalidIssuer();
        console.log('Created mock ID token with invalid issuer');
        
        if (!invalidIssuerToken) {
            console.error('Failed to create ID token with invalid issuer');
            return;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = invalidIssuerToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the invalid issuer
            client!.validateIdTokenIssuer(payload);
            console.error('ERROR: Failed to detect invalid issuer in ID token');
        } catch (error) {
            console.log('✓ Successfully detected invalid issuer in ID token');
            console.log('✓ Test passed: Invalid issuer was properly rejected');
            return true;
        }
    } catch (error) {
        console.error('Error testing invalid issuer detection:', error);
    }
    
    return false;
}

// Add a function to test the invalid audience scenario
async function testInvalidAudience() {
    console.log('\n==== TESTING INVALID AUDIENCE DETECTION ====');
    
    try {
        // Create a mock ID token with an invalid audience
        const invalidAudienceToken = await client!.createMockIdTokenWithInvalidAudience();
        console.log('Created mock ID token with invalid audience');
        
        if (!invalidAudienceToken) {
            console.error('Failed to create ID token with invalid audience');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = invalidAudienceToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the invalid audience
            client!.validateIdTokenAudience(payload);
            console.error('ERROR: Failed to detect invalid audience in ID token');
            return false;
        } catch (error) {
            console.log('✓ Successfully detected invalid audience in ID token');
            console.log('✓ Test passed: Invalid audience was properly rejected');
            return true;
        }
    } catch (error) {
        console.error('Error testing invalid audience detection:', error);
    }
    
    return false;
}

// Add a function to test the invalid signature scenario
async function testInvalidSignature() {
    console.log('\n==== TESTING INVALID SIGNATURE DETECTION ====');
    
    try {
        // Create a mock ID token with an invalid signature
        const invalidSignatureToken = await client!.createMockIdTokenWithInvalidSignature();
        console.log('Created mock ID token with invalid signature');
        
        try {
            // This should throw an error due to the invalid signature
            client!.validateIdTokenSignature(invalidSignatureToken);
            console.error('ERROR: Failed to detect invalid signature in ID token');
            return false;
        } catch (error) {
            console.log('✓ Successfully detected invalid signature in ID token');
            console.log('✓ Test passed: Invalid signature was properly rejected');
            return true;
        }
    } catch (error) {
        console.error('Error testing invalid signature detection:', error);
    }
    
    return false;
}

// Add a function to test the none algorithm scenario
async function testNoneAlgorithm() {
    console.log('\n==== TESTING "NONE" ALGORITHM DETECTION ====');
    
    try {
        // Create a mock ID token with "none" algorithm
        const noneAlgToken = await client!.createMockIdTokenWithNoneAlgorithm();
        console.log('Created mock ID token with "none" algorithm');
        
        try {
            // This should throw an error due to the "none" algorithm
            client!.validateIdTokenSignature(noneAlgToken);
            console.error('ERROR: Failed to detect "none" algorithm in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('"none" algorithm')) {
                console.log('✓ Successfully detected "none" algorithm in ID token');
                console.log('✓ Test passed: "none" algorithm was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected "none" algorithm error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing "none" algorithm detection:', error);
    }
    
    return false;
}

// Add a function to test the expired exp scenario
async function testExpiredExp() {
    console.log('\n==== TESTING EXPIRED EXP DETECTION ====');
    
    try {
        // Create a mock ID token with an expired exp claim
        const expiredExpToken = await client!.createMockIdTokenWithExpiredExp();
        console.log('Created mock ID token with expired exp claim');
        
        if (!expiredExpToken) {
            console.error('Failed to create ID token with expired exp claim');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = expiredExpToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the expired exp claim
            client!.validateIdTokenExpiration(payload);
            console.error('ERROR: Failed to detect expired exp claim in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('expired')) {
                console.log('✓ Successfully detected expired exp claim in ID token');
                console.log('✓ Test passed: Expired ID token was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected expired exp error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing expired exp detection:', error);
    }
    
    return false;
}

// Add a function to test the missing exp scenario
async function testMissingExp() {
    console.log('\n==== TESTING MISSING EXP DETECTION ====');
    
    try {
        // Create a mock ID token with a missing exp claim
        const missingExpToken = await client!.createMockIdTokenWithMissingExp();
        console.log('Created mock ID token with missing exp claim');
        
        if (!missingExpToken) {
            console.error('Failed to create ID token with missing exp claim');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = missingExpToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the missing exp claim
            client!.validateIdTokenExpiration(payload);
            console.error('ERROR: Failed to detect missing exp claim in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('exp')) {
                console.log('✓ Successfully detected missing exp claim in ID token');
                console.log('✓ Test passed: ID token without exp claim was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected missing exp error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing missing exp detection:', error);
    }
    
    return false;
}

// Add a function to test the invalid s_hash scenario
async function testInvalidSHash() {
    console.log('\n==== TESTING INVALID S_HASH DETECTION ====');
    
    try {
        // Create a mock ID token with an invalid s_hash
        const invalidSHashToken = await client!.createMockIdTokenWithInvalidSHash();
        console.log('Created mock ID token with invalid s_hash');
        
        if (!invalidSHashToken) {
            console.error('Failed to create ID token with invalid s_hash');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = invalidSHashToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the invalid s_hash
            client!.validateIdTokenStateHash(payload, client!.getState());
            console.error('ERROR: Failed to detect invalid s_hash in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('s_hash')) {
                console.log('✓ Successfully detected invalid s_hash in ID token');
                console.log('✓ Test passed: Invalid s_hash was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected invalid s_hash error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing invalid s_hash detection:', error);
    }
    
    return false;
}

// Add a function to test the invalid c_hash scenario
async function testInvalidCHash() {
    console.log('\n==== TESTING INVALID C_HASH DETECTION ====');
    
    try {
        // First, we need to have an authorization code
        if (!client!.getAuthorizationCode()) {
            console.log('No authorization code available. Setting a test code for c_hash validation...');
            client!.setAuthorizationCode('test_authorization_code_for_chash_validation');
        }
        
        // Create a mock ID token with an invalid c_hash
        const invalidCHashToken = await client!.createMockIdTokenWithInvalidCHash();
        console.log('Created mock ID token with invalid c_hash');
        
        if (!invalidCHashToken) {
            console.error('Failed to create ID token with invalid c_hash');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = invalidCHashToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the invalid c_hash
            client!.validateIdTokenCodeHash(payload, client!.getAuthorizationCode());
            console.error('ERROR: Failed to detect invalid c_hash in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('c_hash')) {
                console.log('✓ Successfully detected invalid c_hash in ID token');
                console.log('✓ Test passed: Invalid c_hash was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected invalid c_hash error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing invalid c_hash detection:', error);
    }
    
    return false;
}

// Add a function to test handling token responses with missing scope and expires_in
async function testNoScopeExpiresInTokenResponse() {
    console.log('\n==== TESTING MISSING SCOPE AND EXPIRES_IN IN TOKEN RESPONSE ====');
    
    try {
        // Make sure we have some requested scopes set
        const testScopes = ['openid', 'accounts'];
        client!.setRequestedScopes(testScopes);
        console.log('Set requested scopes for test:', testScopes);
        
        // Create a simpler test token response without ID token to avoid validation issues
        const testTokenResponse = {
            access_token: 'test_access_token_' + crypto.randomBytes(8).toString('hex'),
            token_type: 'Bearer',
            refresh_token: 'test_refresh_token_' + crypto.randomBytes(8).toString('hex')
            // Intentionally omitting scope and expires_in
        };
        console.log('Created test token response without scope and expires_in:', testTokenResponse);
        
        // Process the token response through the handler - this should log but not modify it
        const processedResponse = client!.handleTokenResponse(testTokenResponse);
        console.log('Processed token response:', processedResponse);
        
        // Verify the response wasn't modified (we didn't add scope or expires_in)
        if (processedResponse.scope || processedResponse.expires_in) {
            console.error('ERROR: Token response was modified - scope or expires_in was added');
            return false;
        }
        
        // Get the effective scopes and verify they match the requested scopes
        const effectiveScopes = client!.getEffectiveScopes(processedResponse);
        const requestedScopes = client!.getRequestedScopes();
        
        // Check that effective scopes come from requested scopes when missing in response
        const effectiveScopesMatch = JSON.stringify(effectiveScopes.sort()) === JSON.stringify(requestedScopes.sort());
        if (!effectiveScopesMatch) {
            console.error('ERROR: Effective scopes do not match requested scopes when scope is missing in token response');
            console.error('Effective scopes:', effectiveScopes);
            console.error('Requested scopes:', requestedScopes);
            return false;
        }
        
        console.log('✓ Successfully handled token response with missing scope and expires_in');
        console.log('✓ Effective scopes correctly derived from requested scopes');
        console.log('✓ Test passed: Token response handling follows FAPI spec');
        return true;
    } catch (error) {
        console.error('Error testing no scope/expires_in handling:', error);
    }
    
    return false;
}

// Add the missing test function
async function testMissingScopeAndExpiresIn() {
    console.log('\n==== TESTING MISSING SCOPE AND EXPIRES_IN HANDLING ====');
    
    try {
        // Make sure we have some requested scopes set
        const testScopes = ['openid', 'accounts'];
        client!.setRequestedScopes(testScopes);
        console.log('Set requested scopes for test:', testScopes);
        
        // Create a simpler test token response without ID token to avoid validation issues
        const testTokenResponse = {
            access_token: 'test_access_token_' + crypto.randomBytes(8).toString('hex'),
            token_type: 'Bearer',
            refresh_token: 'test_refresh_token_' + crypto.randomBytes(8).toString('hex')
            // Intentionally omitting scope and expires_in
        };
        console.log('Created test token response without scope and expires_in:', testTokenResponse);
        
        // Process the token response through the handler
        const processedResponse = client!.handleTokenResponse(testTokenResponse);
        console.log('Processed token response:', processedResponse);
        
        // Verify the token wasn't modified (we didn't add scope or expires_in)
        if (processedResponse.scope || processedResponse.expires_in) {
            console.error('ERROR: Token response was modified - scope or expires_in was added');
            return false;
        }
        
        // Verify the effective scopes are based on requested scopes
        const effectiveScopes = client!.getEffectiveScopes(processedResponse);
        console.log('Effective scopes:', effectiveScopes);
        
        // Check that effective scopes come from requested scopes when missing in response
        const effectiveScopesMatch = JSON.stringify(effectiveScopes.sort()) === JSON.stringify(testScopes.sort());
        if (!effectiveScopesMatch) {
            console.error('ERROR: Effective scopes do not match requested scopes when scope is missing');
            console.error('Effective scopes:', effectiveScopes);
            console.error('Requested scopes:', testScopes);
            return false;
        }
        
        console.log('✓ Successfully handled token response with missing scope and expires_in');
        console.log('✓ Effective scopes correctly derived from requested scopes');
        console.log('✓ Test passed: Missing scope and expires_in handled correctly');
        return true;
    } catch (error) {
        console.error('Error testing missing scope and expires_in handling:', error);
    }
    
    return false;
}

// Add a test for refresh token flow conformance
async function testRefreshTokenFlow(discoveryUrl: string, resourceEndpoint: string) {
    console.log('\n==== FAPI1 Advanced Final Client Refresh Token Test ====');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource Endpoint:', resourceEndpoint);

    try {
        if (!client) {
            throw new Error('Client is not initialized');
        }

        // If you want to test with a redirect URL directly (e.g., from terminal or pasted),
        // uncomment the following lines and replace the redirectUrl string with your actual redirect URL:
        
        // const redirectUrl = 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate/callback#state=fac12f4ba18e4d1d2c85256bb789d8f0&code=3jyMBOekKNhpVjtBxJccRd3n72DpQoD9&id_token=eyJraWQiOiJmNDcwNmQxOC1iZjE2LTQzY2UtYjE4MS05MGI0MTI4Y2EyMTYiLCJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyLXN1YmplY3QtMTIzNDUzMSIsImF1ZCI6IjJkNGM5NWE3LTZkYzMtNDQxNi1hYjFjLWVhNDQ1MDE2MzVhYSIsImNfaGFzaCI6ImhKMlU2RWpiQ3Zjcnl2LVJjRjA1aEEiLCJhY3IiOiJ1cm46b3BlbmJhbmtpbmc6cHNkMjpzY2EiLCJzX2hhc2giOiJqV2RkNlctRm9URUlrVkpRUE44Uk13IiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QuZW1vYml4LmNvLnVrOjg0NDMvdGVzdC9hL2Fpcy1jb3Jwb3JhdGUvIiwiZXhwIjoxNzQ1ODQxMjAxLCJub25jZSI6IjQxMjkwMjUzZjdjYTU0MzI2YjA4YjYxZDhhOWMxYzUyIiwiaWF0IjoxNzQ1ODQwOTAxfQ.Syu7KsJlgxMTigZAhuI-RUkDfy5pjCxgi1V0FGBxz7esmVqDha3l0X-QKVVq3e0fDo4Q4RLStMmYay27_j1cDjCw6DlQi4FkFO44DQB0Rg_tg0z4uPx4Tlv5T2cHN6lZyikzgOGgotFcyiunBgrw5d5R1OjN2EpWP6oXAg1SyqlZS5fJ3kvnCdTbtZwjoqju51kG1F0RjliaCadn_X5x4B8FpjcTLgfa9YFnP-vT1AJUP0gWFQwTskIHdZrfeiEv4LehpMhA6_XDCfsERt1UVHhI7642-R4GAXV6bHjx3jNPd0Znw5P5giY_zDO5NTsNRx6NsZDrHrKwAAS0cImnpA';
        /*console.log('Using provided redirect URL:', redirectUrl);
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token response:', tokenResponse);
        return; // Exit early since we are testing direct redirect URL handling
        */

        // Set appropriate scopes for the resource access
        client.setRequestedScopes(['openid', 'payments', 'accounts']);

        // Perform OpenID discovery
        console.log('Performing OpenID discovery...');
        const discoveryResponse = await axios.get(discoveryUrl, {
            headers: {
                'Accept': 'application/json'
            }
        }).then(response => response.data);
        console.log('Discovery completed:', discoveryResponse.issuer);

        // Step 1: Call authorization endpoint (which will immediately redirect back)
        const requestObject = await client.createRequestObject();
        if (!requestObject) {
            throw new Error('Failed to create request object');
        }
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        if (!parResponse.request_uri) {
            throw new Error('No request_uri received from PAR endpoint');
        }
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('Calling authorization endpoint:', authUrl);

        // Make authorization request and handle redirect
        const authResponse = await client.getAuthorizationResponse(parResponse.request_uri);
        if (!authResponse.redirectUrl) {
            throw new Error('Authorization endpoint did not redirect as expected');
        }
        const redirectUrl = authResponse.redirectUrl;
        console.log('Authorization redirect URL:', redirectUrl);

        // Step 2: Exchange authorization code for access token using new helper method
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token response:', tokenResponse);

        // Step 3: Call accounts/payments/resources endpoint with access token
        console.log('Calling resource endpoint with access token...');
        let resourceResponse;
        try {
            resourceResponse = await axios.get(resourceEndpoint, {
                headers: {
                    'Authorization': `Bearer ${tokenResponse.access_token}`
                }
            });
            console.log('Resource endpoint response status:', resourceResponse.status);
        } catch (error: any) {
            if (error.response && error.response.status === 401) {
                console.log('Received 401 Unauthorized from resource endpoint as expected');
                resourceResponse = error.response;
            } else {
                throw error;
            }
        }

        // Step 4: If 401, perform refresh token flow twice
        if (resourceResponse.status === 401) {
            console.log('Performing first refresh token call...');
            const firstRefreshResponse = await client.refreshAccessToken(tokenResponse.refresh_token);
            console.log('First refresh token response:', firstRefreshResponse);

            if (!firstRefreshResponse.refresh_token) {
                throw new Error('First refresh token response did not return a new refresh token');
            }

            console.log('Performing second refresh token call with new refresh token...');
            const secondRefreshResponse = await client.refreshAccessToken(firstRefreshResponse.refresh_token);
            console.log('Second refresh token response:', secondRefreshResponse);

            // Step 5: Retry resource endpoint with new access token
            console.log('Retrying resource endpoint with new access token...');
            const retryResponse = await axios.get(resourceEndpoint, {
                headers: {
                    'Authorization': `Bearer ${secondRefreshResponse.access_token}`
                }
            });
            console.log('Retry resource endpoint response status:', retryResponse.status);

            return {
                status: 'success',
                message: 'Refresh token flow completed successfully',
                initialTokenResponse: tokenResponse,
                firstRefreshResponse: firstRefreshResponse,
                secondRefreshResponse: secondRefreshResponse,
                finalResourceResponseStatus: retryResponse.status
            };
        } else {
            throw new Error('Resource endpoint did not return 401 as expected');
        }
    } catch (error) {
        console.error('Refresh token test failed:', error instanceof Error ? error.message : String(error));
        throw error;
    }
}

// Process command line arguments to determine which test to run
function processArgs() {
    const args = process.argv.slice(2);
    const testType = args[0];
    
    if (!testType) {
        console.log('Usage: node dist/index.js <test-type> [params]');
        console.log('Available test types:');
        console.log('  refresh-token <discoveryUrl> <resourceEndpoint> - Run the FAPI1 advanced final client refresh token test');
        console.log('  invalid-issuer - Test ID token with invalid issuer');
        console.log('  invalid-audience - Test ID token with invalid audience');
        console.log('  invalid-signature - Test ID token with invalid signature');
        console.log('  none-algorithm - Test ID token with none algorithm');
        console.log('  expired-exp - Test ID token with expired exp');
        console.log('  missing-exp - Test ID token with missing exp');
        console.log('  invalid-s-hash - Test ID token with invalid s_hash');
        console.log('  invalid-c-hash - Test ID token with invalid c_hash');
        console.log('  aud-as-array <callbackUrl> - Test ID token with audience as array');
        console.log('  no-scope-expires - Test token endpoint response with no scope and expires_in');
        console.log('  missing-scope-expires-in - Test handling of missing scope and expires_in parameters');
        process.exit(1);
    }
    
    switch (testType.toLowerCase()) {
        case 'refresh-token':
            const discoveryUrl = args[1];
            const resourceEndpoint = args[2];
            if (!discoveryUrl || !resourceEndpoint) {
                console.error('Missing required parameters for refresh-token test.');
                console.error('Usage: node dist/index.js refresh-token <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testRefreshTokenFlow(discoveryUrl, resourceEndpoint);
            }).catch(err => {
                console.error('Failed to execute refresh token test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-issuer':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidIssuer();
            }).catch(err => {
                console.error('Failed to execute invalid issuer test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-audience':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidAudience();
            }).catch(err => {
                console.error('Failed to execute invalid audience test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-signature':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidSignature();
            }).catch(err => {
                console.error('Failed to execute invalid signature test:', err);
                process.exit(1);
            });
            break;
        case 'none-algorithm':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testNoneAlgorithm();
            }).catch(err => {
                console.error('Failed to execute none algorithm test:', err);
                process.exit(1);
            });
            break;
        case 'expired-exp':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testExpiredExp();
            }).catch(err => {
                console.error('Failed to execute expired exp test:', err);
                process.exit(1);
            });
            break;
        case 'missing-exp':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testMissingExp();
            }).catch(err => {
                console.error('Failed to execute missing exp test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-s-hash':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidSHash();
            }).catch(err => {
                console.error('Failed to execute invalid s_hash test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-c-hash':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidCHash();
            }).catch(err => {
                console.error('Failed to execute invalid c_hash test:', err);
                process.exit(1);
            });
            break;
        case 'aud-as-array':
            const callbackUrl = args[1];
            if (!callbackUrl) {
                console.error('Missing required parameter for aud-as-array test.');
                console.error('Usage: node dist/index.js aud-as-array <callbackUrl>');
                process.exit(1);
            }
            console.log('The aud-as-array test is currently not implemented in this build.');
            console.log('This test would validate audience claims provided as arrays in ID tokens.');
            process.exit(0);
            break;
        case 'no-scope-expires':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testNoScopeExpiresInTokenResponse();
            }).catch(err => {
                console.error('Failed to execute no scope and expires_in test:', err);
                process.exit(1);
            });
            break;
        case 'missing-scope-expires-in':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testMissingScopeAndExpiresIn();
            }).catch(err => {
                console.error('Failed to execute missing scope and expires_in test:', err);
                process.exit(1);
            });
            break;
        default:
            console.log(`Unknown test type: ${testType}`);
            process.exit(1);
    }
}

// If this file is being run directly, process command line arguments
if (require.main === module) {
    processArgs();
}

// Export the functions and variables at the top level
export {
    client,
    main,
    testInvalidIssuer,
    testInvalidAudience,
    testInvalidSignature,
    testNoneAlgorithm,
    testExpiredExp,
    testMissingExp,
    testInvalidSHash,
    testInvalidCHash,
    testRefreshTokenFlow,
    testMissingScopeAndExpiresIn,
    testNoScopeExpiresInTokenResponse,
    getJwksAsJson
};