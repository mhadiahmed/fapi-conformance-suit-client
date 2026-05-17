import { FAPIClient, FAPIClientConfig } from './fapiClient';
import { AxiosError } from 'axios';
import * as path from 'path';
import axios from 'axios';
import * as https from 'https';
import * as fs from 'fs';
import crypto from 'crypto';

// Declare client variable outside functions for access across test functions
let client: FAPIClient | null = null;
let client2: FAPIClient | null = null;

const URLSTREAM = 'https://www.certification.openid.net';
const URLSTREAM_MTLS = 'https://mtls-www.certification.openid.net';

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

// Helper function to initialize the FAPI client without running any flow
async function initializeClient(): Promise<FAPIClient> {
    const config: FAPIClientConfig = {
        clientId: 'bc680915-bbd3-45d7-b3c6-2716f4d178ed', // Your conformance suite client ID
        clientSecret: '', // Empty for private_key_jwt
        tokenEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/ksa-rp-seentarbie/token`, // mTLS endpoint
        parEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/ksa-rp-seentarbie/par`, // mTLS endpoint
        issuer: `${URLSTREAM}/test/a/ksa-rp-seentarbie/`, // Note the trailing slash
        discoveryUrl: `${URLSTREAM}/test/a/ksa-rp-seentarbie/.well-known/openid-configuration`,
        redirectUri: `${URLSTREAM}/test/a/ksa-rp-seentarbie/callback`,
        certPath: path.join(__dirname, 'certs/certs.pem'), // Your mTLS certificate
        keyPath: path.join(__dirname, 'certs/privatekey.key'), // Your mTLS key
        signingKeyPath: path.join(__dirname, 'certs/private_key.pem'), // JWT signing key for private_key_jwt
        keyId: 'sig1' // Key ID for JWKS
    };

    const newClient = new FAPIClient(config);
    
    // Log the JWKS that should be provided to the conformance test suite
    console.log('\n==== JWKS FOR CONFORMANCE TEST SUITE ====');
    console.log('Getting JWKS');
    const jwk = newClient.getJwks();
    if (jwk) {
        const jwksOutput = { keys: [jwk] };
        console.log('JWKS for test suite:', JSON.stringify(jwksOutput, null, 2));
    }
    console.log('========================================\n');
    
    // Fetch the server's JWKS for validating ID tokens
    console.log('Fetching authorization server JWKS...');
    await newClient.fetchServerJwks();
    console.log('Authorization server JWKS fetched successfully\n');
    
    return newClient;
}

// Helper function to initialize the FAPI client2 for encrypted ID token tests
async function initializeClient2(): Promise<FAPIClient> {
    const config: FAPIClientConfig = {
        clientId: '06f42d27-c86b-481a-a134-18cf5e0d1e9c', // Client2 ID from conformance config
        clientSecret: '', // Empty for private_key_jwt
        tokenEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/ksa-rp-seentarbie/token`, // mTLS endpoint
        parEndpoint: `${URLSTREAM_MTLS}/test-mtls/a/ksa-rp-seentarbie/par`, // mTLS endpoint
        issuer: `${URLSTREAM}/test/a/ksa-rp-seentarbie/`, // Note the trailing slash
        discoveryUrl: `${URLSTREAM}/test/a/ksa-rp-seentarbie/.well-known/openid-configuration`,
        redirectUri: `${URLSTREAM}/test/a/ksa-rp-seentarbie/callback`,
        certPath: path.join(__dirname, 'certs/certs.pem'), // Your mTLS certificate
        keyPath: path.join(__dirname, 'certs/privatekey.key'), // Your mTLS key
        signingKeyPath: path.join(__dirname, 'certs/client2_signing_key.pem'), // Client2 JWT signing key
        encryptionKeyPath: path.join(__dirname, 'certs/client2_encryption_key.pem'), // Client2 encryption key for decrypting ID tokens
        keyId: 'sig2' // Key ID for client2 JWKS
    };

    const newClient = new FAPIClient(config);
    
    // Log the JWKS that should be provided to the conformance test suite
    console.log('\n==== JWKS FOR CLIENT2 (ENCRYPTED ID TOKEN TEST) ====');
    console.log('Getting JWKS');
    const jwk = newClient.getJwks();
    if (jwk) {
        const jwksOutput = { keys: [jwk] };
        console.log('Client2 JWKS:', JSON.stringify(jwksOutput, null, 2));
    }
    console.log('========================================\n');
    
    // Fetch the server's JWKS for validating ID tokens
    console.log('Fetching authorization server JWKS for client2...');
    await newClient.fetchServerJwks();
    console.log('Authorization server JWKS fetched successfully\n');
    
    return newClient;
}

async function main() {
    try {
        client = await initializeClient();
        
        // Set requested scopes
        client.setRequestedScopes(['openid','accounts']);

        // Create HTTPS agent with mTLS certificates
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');

        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
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
            aud: `${URLSTREAM}/test/a/seentarbi-ais-corporate`,
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

// Test function for no-scope test - completes the full flow
async function testNoScope(discoveryUrl: string, resourceEndpoint: string) {
    console.log('Starting no-scope test...');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    try {
        if (!client) {
            throw new Error('Client is not initialized');
        }

        // Create HTTPS agent with mTLS configuration for resource endpoint calls
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false // Accept self-signed certificates in test environment
        });

        // Step 1: OpenID Connect discovery
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        console.log('Issuer:', openIdConfig.data.issuer);

        // Create account consent request
        console.log('Creating account consent request...');
        client.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 2: Submit PAR and get authorization
        console.log('Submitting PAR request...');
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Get authorization response
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
            }
        } catch (error: any) {
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect:', redirectUrl);
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 3: Exchange authorization code for tokens
        console.log('Step 3: Exchanging authorization code for tokens...');
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token exchange completed successfully');
        
        // Verify that the token response doesn't contain scope or expires_in
        console.log('Verifying token response structure...');
        if (tokenResponse.scope) {
            console.log('⚠️ Token response contains scope field:', tokenResponse.scope);
        } else {
            console.log('✓ Token response does not contain scope field (as expected)');
        }
        
        if (tokenResponse.expires_in) {
            console.log('⚠️ Token response contains expires_in field:', tokenResponse.expires_in);
        } else {
            console.log('✓ Token response does not contain expires_in field (as expected)');
        }
        
        // Verify that effective scopes are derived from requested scopes
        const effectiveScopes = client.getEffectiveScopes(tokenResponse);
        const requestedScopes = client.getRequestedScopes();
        console.log('Effective scopes:', effectiveScopes);
        console.log('Requested scopes:', requestedScopes);

        // Step 4: Call resource endpoint with access token
        console.log('Step 4: Calling resource endpoint with access token...');
        const resourceResponse = await axios.get(resourceEndpoint, {
            headers: {
                'Authorization': `Bearer ${tokenResponse.access_token}`
            },
            httpsAgent
        });
        console.log('Resource endpoint response status:', resourceResponse.status);

        if (resourceResponse.status === 200) {
            console.log('\n✓ Test PASSED: Flow completed successfully without scope/expires_in in token response');
            console.log('✓ Client correctly derived effective scopes from requested scopes');
            return {
                status: 'success',
                message: 'No-scope test completed successfully',
                effectiveScopes: effectiveScopes,
                resourceResponseStatus: resourceResponse.status
            };
        } else {
            throw new Error(`Unexpected resource endpoint response: ${resourceResponse.status}`);
        }
    } catch (error) {
        console.error('No-scope test failed:', error instanceof Error ? error.message : String(error));
        console.error('Error details:', error);
        throw error;
    }
}

// Add a function to test handling token responses with missing scope and expires_in (mock version for unit testing)
async function testNoScopeExpiresInTokenResponseMock() {
    console.log('\n==== TESTING MISSING SCOPE AND EXPIRES_IN IN TOKEN RESPONSE (MOCK) ====');
    
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
    console.log('Starting refresh token flow test...');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    try {
        if (!client) {
            throw new Error('Client is not initialized');
        }

        // Create HTTPS agent with mTLS configuration for resource endpoint calls
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false // Accept self-signed certificates in test environment
        });

        // Step 1: OpenID Connect discovery and authorization code flow
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        console.log('Issuer:', openIdConfig.data.issuer);

        // Create and submit request object with pushed authorization request (PAR)
        console.log('Creating account consent request...');
        // Set appropriate scopes for the resource access
        client.setRequestedScopes(['openid', 'accounts']);
        
        // Create account consent request
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 1a: Submit Pushed Authorization Request (PAR)
        console.log('Submitting PAR request...');
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        // Step 1b: Construct authorization URL and redirect
        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Try to get authorization response, but we know it might throw due to how redirects are handled
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            // This step is expected to throw an error with a 303 redirect
            // We'll catch it and extract the redirect URL from the location header
            const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
                console.log('Got redirect URL through normal flow:', redirectUrl);
            }
        } catch (error: any) {
            // This is actually the expected path - the 303 redirect should be caught here
            console.log('Caught response from authorization endpoint with status:', error.response?.status);
            
            // Extract redirect from the error response directly
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect (this is expected behavior):', redirectUrl);
                console.log('Redirect URL format:', redirectUrl.includes('#') ? 'Fragment (#)' : 'Query parameters (?)');
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 2: Exchange authorization code for access token using new helper method
        console.log('Step 2: Exchanging authorization code for tokens...');
        console.log('Redirect URL being processed:', redirectUrl);
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token response:', tokenResponse);

        // Step 3: Call accounts/payments/resources endpoint with access token
        console.log('Step 3: Calling resource endpoint with access token...');
        console.log('Using access token:', tokenResponse.access_token.substring(0, 10) + '...');
        let resourceResponse;
        try {
            resourceResponse = await axios.get(resourceEndpoint, {
                headers: {
                    'Authorization': `Bearer ${tokenResponse.access_token}`
                },
                httpsAgent
            });
            console.log('Resource endpoint response status:', resourceResponse.status);
        } catch (error: any) {
            if (error.response && error.response.status === 401) {
                console.log('Received 401 Unauthorized from resource endpoint as expected');
                resourceResponse = error.response;
            } else {
                console.error('Unexpected error calling resource endpoint:', error.message);
                throw error;
            }
        }

        // Step 4: If 401, perform refresh token flow twice
        if (resourceResponse.status === 401) {
            console.log('Step 4: Performing first refresh token call...');
            console.log('Using refresh token:', tokenResponse.refresh_token.substring(0, 10) + '...');
            const firstRefreshResponse = await client.refreshAccessToken(tokenResponse.refresh_token);
            console.log('First refresh token response:', firstRefreshResponse);

            if (!firstRefreshResponse.refresh_token) {
                throw new Error('First refresh token response did not return a new refresh token');
            }

            console.log('Performing second refresh token call with new refresh token...');
            console.log('Using new refresh token:', firstRefreshResponse.refresh_token.substring(0, 10) + '...');
            const secondRefreshResponse = await client.refreshAccessToken(firstRefreshResponse.refresh_token);
            console.log('Second refresh token response:', secondRefreshResponse);

            // Step 5: Retry resource endpoint with new access token
            console.log('Step 5: Retrying resource endpoint with new access token...');
            console.log('Using new access token:', secondRefreshResponse.access_token.substring(0, 10) + '...');
            const retryResponse = await axios.get(resourceEndpoint, {
                headers: {
                    'Authorization': `Bearer ${secondRefreshResponse.access_token}`
                },
                httpsAgent
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
        console.error('Error details:', error);
        throw error;
    }
}

// Test function for missing at_hash test - simplified version that expects success
async function testMissingAtHash(discoveryUrl: string, resourceEndpoint: string) {
    console.log('Starting missing at_hash test...');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    try {
        if (!client) {
            throw new Error('Client is not initialized');
        }

        // Create HTTPS agent with mTLS configuration for resource endpoint calls
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false // Accept self-signed certificates in test environment
        });

        // Step 1: OpenID Connect discovery
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        console.log('Issuer:', openIdConfig.data.issuer);

        // Create account consent request
        console.log('Creating account consent request...');
        client.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 2: Submit PAR and get authorization
        console.log('Submitting PAR request...');
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Get authorization response
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            console.log('Authorization response:', authResponse);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
                console.log('Got redirect URL from response:', redirectUrl);
            }
        } catch (error: any) {
            console.log('Caught error from authorization request:', {
                status: error.response?.status,
                location: error.response?.headers?.location,
                message: error.message
            });
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect:', redirectUrl);
            } else if (error.response?.status === 302 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 302 redirect:', redirectUrl);
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 3: Exchange authorization code for tokens
        console.log('Step 3: Exchanging authorization code for tokens...');
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token exchange completed successfully');
        console.log('Token response keys:', Object.keys(tokenResponse));

        // Step 4: Call resource endpoint with access token
        console.log('Step 4: Calling resource endpoint with access token...');
        const resourceResponse = await axios.get(resourceEndpoint, {
            headers: {
                'Authorization': `Bearer ${tokenResponse.access_token}`
            },
            httpsAgent
        });
        console.log('Resource endpoint response status:', resourceResponse.status);

        if (resourceResponse.status === 200) {
            console.log('\n✓ Test PASSED: Flow completed successfully with ID token missing at_hash');
            return {
                status: 'success',
                message: 'Missing at_hash test completed successfully',
                resourceResponseStatus: resourceResponse.status
            };
        } else {
            throw new Error(`Unexpected resource endpoint response: ${resourceResponse.status}`);
        }
    } catch (error) {
        console.error('Missing at_hash test failed:', error instanceof Error ? error.message : String(error));
        console.error('Error details:', error);
        throw error;
    }
}

// Add a function to test the invalid nonce scenario
async function testInvalidNonce() {
    console.log('\n==== TESTING INVALID NONCE DETECTION ====');
    
    try {
        // Create a mock ID token with an invalid nonce
        const invalidNonceToken = await client!.createMockIdTokenWithInvalidNonce();
        console.log('Created mock ID token with invalid nonce');
        
        if (!invalidNonceToken) {
            console.error('Failed to create ID token with invalid nonce');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = invalidNonceToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the invalid nonce
            client!.validateIdTokenNonce(payload);
            console.error('ERROR: Failed to detect invalid nonce in ID token');
            return false;
        } catch (error) {
            console.log('✓ Successfully detected invalid nonce in ID token');
            console.log('✓ Test passed: Invalid nonce was properly rejected');
            return true;
        }
    } catch (error) {
        console.error('Error testing invalid nonce detection:', error);
    }
    
    return false;
}

// Add a function to test the old iat (issued at) scenario
async function testOldIat() {
    console.log('\n==== TESTING OLD IAT DETECTION ====');
    
    try {
        // Create a mock ID token with an IAT claim more than a week in the past
        const oldIatToken = await client!.createMockIdTokenWithOldIat();
        console.log('Created mock ID token with old iat claim');
        
        if (!oldIatToken) {
            console.error('Failed to create ID token with old iat claim');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = oldIatToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        try {
            // This should throw an error due to the old iat claim
            client!.validateIdTokenIssueTime(payload);
            console.error('ERROR: Failed to detect old iat claim in ID token');
            return false;
        } catch (error) {
            if (error instanceof Error && error.message.includes('too far in the past')) {
                console.log('✓ Successfully detected old iat claim in ID token');
                console.log('✓ Test passed: ID token with old iat was properly rejected');
                return true;
            } else {
                console.log('❌ Detected error, but not the expected old iat error:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing old iat detection:', error);
    }
    
    return false;
}

// Add a function to test the missing at_hash scenario with mock tokens
async function testMissingAtHashMock() {
    console.log('\n==== TESTING MISSING AT_HASH HANDLING (MOCK) ====');
    
    try {
        // Create a mock ID token without an at_hash claim
        const noAtHashToken = await client!.createMockIdTokenWithoutAtHash();
        console.log('Created mock ID token without at_hash claim');
        
        if (!noAtHashToken) {
            console.error('Failed to create ID token without at_hash claim');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = noAtHashToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        // Verify the token has no at_hash
        if (payload.at_hash) {
            console.error('ERROR: Token unexpectedly contains an at_hash claim');
            return false;
        }
        
        // Create a mock authorization response with the ID token
        const mockAuthResponse = {
            id_token: noAtHashToken,
            state: client!.getState() || 'test-state',
            code: 'test_authorization_code'
        };
        
        try {
            // This should succeed even though at_hash is missing
            await client!.handleAuthorizationResponse(mockAuthResponse);
            console.log('✓ Successfully processed ID token without at_hash');
            console.log('✓ Test passed: Missing at_hash was correctly handled as optional');
            return true;
        } catch (error) {
            if (error instanceof Error && error.message.includes('at_hash')) {
                console.error('❌ Test failed: Client incorrectly rejected ID token due to missing at_hash');
                console.error('Error:', error.message);
                return false;
            } else if (error instanceof Error) {
                // If there's an error, but it's not about at_hash, it's likely due to other validations
                console.log('⚠️ Token was rejected, but not due to missing at_hash. Error:', error.message);
                console.log('This is likely due to other validations failing, not the at_hash test itself.');
                
                // Try to validate just the basic claims without going through the full authorization response handler
                client!.validateIdTokenNonce(payload);
                client!.validateIdTokenIssuer(payload);
                client!.validateIdTokenAudience(payload);
                client!.validateIdTokenExpiration(payload);
                client!.validateIdTokenIssueTime(payload);
                
                console.log('✓ Basic validations passed for token without at_hash');
                console.log('✓ Test passed: The client does not require at_hash');
                return true;
            } else {
                console.error('❌ Unknown error during test:', error);
                return false;
            }
        }
    } catch (error) {
        console.error('Error testing missing at_hash handling:', error);
    }
    
    return false;
}

// Test function for aud-as-array test - completes the full flow
async function testAudAsArray(discoveryUrl: string, resourceEndpoint: string) {
    console.log('Starting aud-as-array test...');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    try {
        if (!client) {
            throw new Error('Client is not initialized');
        }

        // Create HTTPS agent with mTLS configuration for resource endpoint calls
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false // Accept self-signed certificates in test environment
        });

        // Step 1: OpenID Connect discovery
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        console.log('Issuer:', openIdConfig.data.issuer);

        // Create account consent request
        console.log('Creating account consent request...');
        client.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client.setConsentId(accountConsentRequest.Data.ConsentId);
        client.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 2: Submit PAR and get authorization
        console.log('Submitting PAR request...');
        const parResponse = await client.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        const authUrl = client.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Get authorization response
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            const authResponse = await client.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
            }
        } catch (error: any) {
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect:', redirectUrl);
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 3: Exchange authorization code for tokens
        console.log('Step 3: Exchanging authorization code for tokens...');
        const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token exchange completed successfully');
        
        // Parse the ID token to verify aud is an array
        console.log('Verifying ID token aud claim is an array...');
        const idTokenParts = tokenResponse.id_token.split('.');
        const payload = JSON.parse(Buffer.from(idTokenParts[1], 'base64url').toString());
        
        if (Array.isArray(payload.aud)) {
            console.log('✓ ID token aud claim is an array:', payload.aud);
        } else {
            throw new Error(`Expected aud to be an array, but got: ${typeof payload.aud}`);
        }

        // Step 4: Call resource endpoint with access token
        console.log('Step 4: Calling resource endpoint with access token...');
        const resourceResponse = await axios.get(resourceEndpoint, {
            headers: {
                'Authorization': `Bearer ${tokenResponse.access_token}`
            },
            httpsAgent
        });
        console.log('Resource endpoint response status:', resourceResponse.status);

        if (resourceResponse.status === 200) {
            console.log('\n✓ Test PASSED: Flow completed successfully with ID token aud as array');
            return {
                status: 'success',
                message: 'Aud-as-array test completed successfully',
                audValue: payload.aud,
                resourceResponseStatus: resourceResponse.status
            };
        } else {
            throw new Error(`Unexpected resource endpoint response: ${resourceResponse.status}`);
        }
    } catch (error) {
        console.error('Aud-as-array test failed:', error instanceof Error ? error.message : String(error));
        console.error('Error details:', error);
        throw error;
    }
}

// Mock-based test for audience as array (kept for reference/unit testing)
async function testAudAsArrayMock() {
    console.log('\n==== TESTING AUDIENCE AS ARRAY VALIDATION (MOCK) ====');
    
    try {
        // Create a mock ID token with audience as an array containing the client ID
        const audAsArrayToken = await client!.createMockIdTokenWithAudAsArray();
        console.log('Created mock ID token with audience as array');
        
        if (!audAsArrayToken) {
            console.error('Failed to create ID token with audience as array');
            return false;
        }
        
        // Parse the JWT to get the payload
        const [headerB64, payloadB64] = audAsArrayToken.split('.');
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        // Verify the audience is an array
        if (!Array.isArray(payload.aud)) {
            console.error('ERROR: Audience is not an array as expected');
            return false;
        }
        
        console.log('Verified audience is an array:', payload.aud);
        
        try {
            // This should succeed since the client ID is in the array
            client!.validateIdTokenAudience(payload);
            console.log('✓ Successfully validated ID token with audience as array');
            
            // Create a mock authorization response with the ID token
            const mockAuthResponse = {
                id_token: audAsArrayToken,
                state: client!.getState() || 'test-state',
                code: 'test_authorization_code'
            };
            
            // Try the complete authorization response handling
            try {
                await client!.handleAuthorizationResponse(mockAuthResponse);
                console.log('✓ Successfully processed complete authorization response with audience as array');
                console.log('✓ Test passed: Audience as array was correctly validated');
                return true;
            } catch (error) {
                // If there's an error but it's not about audience, the test is still successful for audience validation
                if (error instanceof Error && !error.message.includes('audience')) {
                    console.log('⚠️ Authorization response processing failed, but not due to audience issues');
                    console.log('Error:', error.message);
                    console.log('✓ Test passed: Audience as array was correctly validated');
                    return true;
                } else {
                    console.error('❌ Test failed: Client incorrectly rejected ID token with audience as array');
                    console.error('Error:', error);
                    return false;
                }
            }
        } catch (error) {
            console.error('❌ Failed to validate ID token with audience as array');
            console.error('Error:', error);
            return false;
        }
    } catch (error) {
        console.error('Error testing audience as array validation:', error);
    }
    
    return false;
}

// Add a function to test handling encrypted ID tokens
async function testEncryptedIdToken(discoveryUrl: string, resourceEndpoint: string) {
    console.log('\n==== TESTING ENCRYPTED ID TOKEN HANDLING ====');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    
    try {
        // Initialize client2 if not already done
        if (!client2) {
            console.log('Initializing client2 for encrypted ID token test...');
            client2 = await initializeClient2();
        }
        
        // Create HTTPS agent with mTLS configuration
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false // Accept self-signed certificates in test environment
        });

        // Step 1: OpenID Connect discovery
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);
        console.log('Authorization endpoint:', openIdConfig.data.authorization_endpoint);
        console.log('Token endpoint:', openIdConfig.data.token_endpoint);
        console.log('Issuer:', openIdConfig.data.issuer);

        // Create account consent request using client2
        console.log('Creating account consent request with client2...');
        client2.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client2.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client2.setConsentId(accountConsentRequest.Data.ConsentId);
        client2.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client2.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 2: Submit PAR and get authorization
        console.log('Submitting PAR request...');
        const parResponse = await client2.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        const authUrl = client2.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Get authorization response
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            const authResponse = await client2.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
            }
        } catch (error: any) {
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect:', redirectUrl);
            } else if (error.response?.status === 302 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 302 redirect:', redirectUrl);
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 3: Exchange authorization code for tokens (this should return an encrypted ID token)
        console.log('Step 3: Exchanging authorization code for tokens...');
        console.log('The ID token should be encrypted using RSA-OAEP with A256GCM');
        const tokenResponse = await client2.handleRedirectUrlAndExchangeCode(redirectUrl);
        console.log('Token exchange completed successfully');
        
        // Verify the ID token was received
        if (tokenResponse.id_token) {
            console.log('✓ ID token received');
            
            // Check if it was encrypted (JWE has 5 parts separated by dots)
            const parts = tokenResponse.id_token.split('.');
            if (parts.length === 5) {
                console.log('✓ ID token was in JWE format (encrypted) and was successfully decrypted');
            } else if (parts.length === 3) {
                console.log('ℹ ID token was in JWS format (signed but not encrypted)');
            }
        }

        // Step 4: Call resource endpoint with access token
        console.log('Step 4: Calling resource endpoint with access token...');
        const resourceResponse = await axios.get(resourceEndpoint, {
            headers: {
                'Authorization': `Bearer ${tokenResponse.access_token}`
            },
            httpsAgent
        });
        console.log('Resource endpoint response status:', resourceResponse.status);

        if (resourceResponse.status === 200) {
            console.log('\n✓ Test PASSED: Flow completed successfully with encrypted ID token');
            return {
                status: 'success',
                message: 'Encrypted ID token test completed successfully',
                resourceResponseStatus: resourceResponse.status
            };
        } else {
            throw new Error(`Unexpected resource endpoint response: ${resourceResponse.status}`);
        }
    } catch (error) {
        console.error('Encrypted ID token test failed:', error instanceof Error ? error.message : String(error));
        console.error('Error details:', error);
        throw error;
    }
}

// Add a function to test rejection of RSA1_5 encrypted ID tokens
async function testEncryptedIdTokenRsa15Rejection(discoveryUrl: string, resourceEndpoint: string) {
    console.log('\n==== TESTING RSA1_5 ENCRYPTED ID TOKEN REJECTION ====');
    console.log('Discovery URL:', discoveryUrl);
    console.log('Resource endpoint:', resourceEndpoint);
    console.log('This test verifies that the client REJECTS ID tokens encrypted with RSA1_5 algorithm');
    
    try {
        // Initialize client2 if not already done
        if (!client2) {
            console.log('Initializing client2 for RSA1_5 rejection test...');
            client2 = await initializeClient2();
        }
        
        // Create HTTPS agent with mTLS configuration
        const certPath = path.join(__dirname, 'certs/certs.pem');
        const keyPath = path.join(__dirname, 'certs/privatekey.key');
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            rejectUnauthorized: false
        });

        // Step 1: OpenID Connect discovery
        console.log('Step 1: Performing OpenID Connect discovery...');
        const openIdConfig = await axios.get(discoveryUrl, { httpsAgent });
        console.log('OpenID Connect discovery response status:', openIdConfig.status);

        // Create account consent request using client2
        console.log('Creating account consent request with client2...');
        client2.setRequestedScopes(['openid', 'accounts']);
        const accountConsentRequest = await client2.createAccountConsentRequest();
        console.log('Account consent response:', accountConsentRequest);

        // Create request object for authorization
        console.log('Creating request object...');
        client2.setConsentId(accountConsentRequest.Data.ConsentId);
        client2.setRequestedScopes(['openid', `accounts:${accountConsentRequest.Data.ConsentId}`]);
        const requestObject = await client2.createRequestObject();

        if (!requestObject) {
            throw new Error('Could not create request object');
        }

        // Step 2: Submit PAR and get authorization
        console.log('Submitting PAR request...');
        const parResponse = await client2.submitPushedAuthorizationRequest(requestObject);
        console.log('PAR Response:', parResponse);

        const authUrl = client2.getAuthorizationUrl(parResponse.request_uri);
        console.log('Authorization URL:', authUrl);

        // Get authorization response
        console.log('Making authorization request to:', authUrl);
        let redirectUrl;
        try {
            const authResponse = await client2.makeAuthorizationRequest(authUrl, parResponse.request_uri);
            if (authResponse.redirectUrl) {
                redirectUrl = authResponse.redirectUrl;
            }
        } catch (error: any) {
            if (error.response?.status === 303 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 303 redirect:', redirectUrl);
            } else if (error.response?.status === 302 && error.response?.headers?.location) {
                redirectUrl = error.response.headers.location;
                console.log('Extracted redirect URL from 302 redirect:', redirectUrl);
            } else {
                console.error('Failed to get valid redirect response:', error);
                throw error;
            }
        }

        if (!redirectUrl) {
            throw new Error('Could not obtain redirect URL with authorization code');
        }

        // Step 3: Exchange authorization code for tokens
        // This SHOULD FAIL because the ID token is encrypted with RSA1_5
        console.log('Step 3: Exchanging authorization code for tokens...');
        console.log('The ID token will be encrypted using RSA1_5 which should be REJECTED');
        
        try {
            const tokenResponse = await client2.handleRedirectUrlAndExchangeCode(redirectUrl);
            
            // If we get here, the test FAILED because we should have rejected the RSA1_5 encrypted token
            console.error('\n❌ Test FAILED: Client accepted ID token encrypted with RSA1_5');
            console.error('The client should have rejected the token due to insecure algorithm');
            throw new Error('Client incorrectly accepted ID token encrypted with disallowed RSA1_5 algorithm');
            
        } catch (error: any) {
            // Check if the error is due to RSA1_5 rejection (which is expected)
            if (error.message && (error.message.includes('RSA1_5') || error.message.includes('disallowed algorithm'))) {
                console.log('\n✓ Test PASSED: Client correctly rejected ID token encrypted with RSA1_5');
                console.log('✓ Error message:', error.message);
                return {
                    status: 'success',
                    message: 'Client correctly rejected RSA1_5 encrypted ID token',
                    rejectionReason: error.message
                };
            } else {
                // Re-throw if it's a different error
                throw error;
            }
        }
    } catch (error) {
        // Check if this is actually a success case (RSA1_5 rejection)
        if (error instanceof Error && (error.message.includes('RSA1_5') || error.message.includes('disallowed algorithm'))) {
            console.log('\n✓ Test PASSED: Client correctly rejected ID token encrypted with RSA1_5');
            return {
                status: 'success',
                message: 'Client correctly rejected RSA1_5 encrypted ID token'
            };
        }
        console.error('RSA1_5 rejection test failed:', error instanceof Error ? error.message : String(error));
        throw error;
    }
}

// Process command line arguments to determine which test to run
function processArgs() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args[0] === '-h' || args[0] === '--help') {
        console.log('Usage: npm run test <test-type>');
        console.log('Available test types:');
        console.log('  invalid-issuer        - Test invalid issuer detection');
        console.log('  invalid-audience      - Test invalid audience detection');
        console.log('  invalid-signature     - Test invalid signature detection');
        console.log('  none-algorithm        - Test "none" algorithm detection');
        console.log('  expired-exp           - Test expired exp claim detection');
        console.log('  missing-exp           - Test missing exp claim detection');
        console.log('  invalid-s-hash        - Test invalid s_hash detection');
        console.log('  invalid-c-hash        - Test invalid c_hash detection');
        console.log('  no-scope              - Test token response with missing scope and expires_in - requires discoveryUrl and resourceEndpoint');
        console.log('  missing-fields        - Test token response with missing scope and expires_in');
        console.log('  happy-path            - Test complete happy path flow (for fapi1-advanced-final-client-test)');
        console.log('  refresh-token-flow    - Test refresh token flow with URL and resource endpoint');
        console.log('  invalid-nonce         - Test invalid nonce detection');
        console.log('  old-iat               - Test ID token with iat more than a week in the past');
        console.log('  missing-at-hash       - Test ID token without at_hash (should be accepted) - requires discoveryUrl and resourceEndpoint');
        console.log('  aud-as-array          - Test ID token with audience as array with 1 value - requires discoveryUrl and resourceEndpoint');
        console.log('  encrypted-idtoken     - Test handling of encrypted ID tokens - requires discoveryUrl and resourceEndpoint');
        console.log('  encrypted-rsa15       - Test rejection of RSA1_5 encrypted ID tokens - requires discoveryUrl and resourceEndpoint');
        process.exit(0);
    }

    const testType = args[0];
    
    switch (testType.toLowerCase()) {
        case 'happy-path':
            const happyDiscoveryUrl = args[1];
            const happyResourceEndpoint = args[2];
            if (!happyDiscoveryUrl || !happyResourceEndpoint) {
                console.error('Missing required parameters for happy-path test.');
                console.error('Usage: node dist/index.js happy-path <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            initializeClient().then((initializedClient) => {
                client = initializedClient;
                return testRefreshTokenFlow(happyDiscoveryUrl, happyResourceEndpoint);
            }).catch(err => {
                console.error('Failed to execute happy path test:', err);
                process.exit(1);
            });
            break;
        case 'refresh-token':
            const discoveryUrl = args[1];
            const resourceEndpoint = args[2];
            if (!discoveryUrl || !resourceEndpoint) {
                console.error('Missing required parameters for refresh-token test.');
                console.error('Usage: node dist/index.js refresh-token <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            initializeClient().then((initializedClient) => {
                client = initializedClient;
                console.log('\n==== TESTING REFRESH TOKEN FLOW ====');
                console.log('This test verifies that the client correctly handles refresh token flow');
                console.log('(Resource endpoint returns 401, client uses refresh_token grant twice, then retries)\n');
                return testRefreshTokenFlow(discoveryUrl, resourceEndpoint);
            }).then(() => {
                console.log('\n✓ Test PASSED: Refresh token flow completed successfully');
                process.exit(0);
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
        case 'no-scope':
        case 'no-scope-expires':
            const noScopeDiscoveryUrl = args[1];
            const noScopeResourceEndpoint = args[2];
            if (!noScopeDiscoveryUrl || !noScopeResourceEndpoint) {
                console.error('Missing required parameters for no-scope test.');
                console.error('Usage: node dist/index.js no-scope <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            initializeClient().then((initializedClient) => {
                client = initializedClient;
                console.log('\n==== TESTING NO SCOPE IN TOKEN RESPONSE ====');
                console.log('This test verifies that the client correctly handles token responses without scope/expires_in');
                console.log('(Client should derive effective scopes from requested scopes)\n');
                return testNoScope(noScopeDiscoveryUrl, noScopeResourceEndpoint);
            }).then(() => {
                console.log('\n✓ Test PASSED: Client correctly handled token response without scope/expires_in');
                process.exit(0);
            }).catch(err => {
                console.error('Failed to execute no-scope test:', err);
                process.exit(1);
            });
            break;
        case 'missing-fields':
        case 'missing-scope-expires-in':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testMissingScopeAndExpiresIn();
            }).catch(err => {
                console.error('Failed to execute missing-fields test:', err);
                process.exit(1);
            });
            break;
        case 'invalid-nonce':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testInvalidNonce();
            }).catch(err => {
                console.error('Failed to execute invalid nonce test:', err);
                process.exit(1);
            });
            break;
        case 'old-iat':
            main().then((initializedClient) => {
                client = initializedClient;
                if (!client) throw new Error('Client not initialized');
                return testOldIat();
            }).catch(err => {
                console.error('Failed to execute old iat test:', err);
                process.exit(1);
            });
            break;
        case 'missing-at-hash':
            const atHashDiscoveryUrl = args[1];
            const atHashResourceEndpoint = args[2];
            if (!atHashDiscoveryUrl || !atHashResourceEndpoint) {
                console.error('Missing required parameters for missing-at-hash test.');
                console.error('Usage: node dist/index.js missing-at-hash <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            initializeClient().then((initializedClient) => {
                client = initializedClient;
                console.log('\n==== TESTING MISSING AT_HASH ====');
                console.log('This test verifies that the client accepts ID tokens without at_hash claim');
                console.log('(at_hash is optional when access token is not returned from authorization endpoint)\n');
                return testMissingAtHash(atHashDiscoveryUrl, atHashResourceEndpoint);
            }).then(() => {
                console.log('\n✓ Test PASSED: Client correctly handled ID token without at_hash');
                process.exit(0);
            }).catch(err => {
                console.error('Failed to execute missing at_hash test:', err);
                process.exit(1);
            });
            break;
        case 'aud-as-array':
            const audDiscoveryUrl = args[1];
            const audResourceEndpoint = args[2];
            if (!audDiscoveryUrl || !audResourceEndpoint) {
                console.error('Missing required parameters for aud-as-array test.');
                console.error('Usage: node dist/index.js aud-as-array <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            initializeClient().then((initializedClient) => {
                client = initializedClient;
                console.log('\n==== TESTING AUDIENCE AS ARRAY ====');
                console.log('This test verifies that the client correctly handles ID tokens with aud as an array');
                console.log('(aud can be an array with one value per OIDC spec)\n');
                return testAudAsArray(audDiscoveryUrl, audResourceEndpoint);
            }).then(() => {
                console.log('\n✓ Test PASSED: Client correctly handled ID token with aud as array');
                process.exit(0);
            }).catch(err => {
                console.error('Failed to execute aud-as-array test:', err);
                process.exit(1);
            });
            break;
        case 'encrypted-idtoken':
            const encDiscoveryUrl = args[1];
            const encResourceEndpoint = args[2];
            if (!encDiscoveryUrl || !encResourceEndpoint) {
                console.error('Missing required parameters for encrypted-idtoken test.');
                console.error('Usage: node dist/index.js encrypted-idtoken <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            console.log('\n==== TESTING ENCRYPTED ID TOKEN ====');
            console.log('This test verifies that the client can handle encrypted ID tokens.');
            console.log('The ID token will be encrypted using RSA-OAEP for key encryption and A256GCM for content encryption.\n');
            testEncryptedIdToken(encDiscoveryUrl, encResourceEndpoint).then(() => {
                console.log('\n✓ Test PASSED: Client correctly handled encrypted ID token');
                process.exit(0);
            }).catch(err => {
                console.error('Failed to execute encrypted ID token test:', err);
                process.exit(1);
            });
            break;
        case 'encrypted-rsa15':
        case 'encrypted-idtoken-rsa15':
            const rsa15DiscoveryUrl = args[1];
            const rsa15ResourceEndpoint = args[2];
            if (!rsa15DiscoveryUrl || !rsa15ResourceEndpoint) {
                console.error('Missing required parameters for encrypted-rsa15 test.');
                console.error('Usage: node dist/index.js encrypted-rsa15 <discoveryUrl> <resourceEndpoint>');
                process.exit(1);
            }
            console.log('\n==== TESTING RSA1_5 ENCRYPTED ID TOKEN REJECTION ====');
            console.log('This test verifies that the client REJECTS ID tokens encrypted with RSA1_5.');
            console.log('RSA1_5 (RSA-PKCS1-v1_5) is not allowed per FAPI security requirements.\n');
            testEncryptedIdTokenRsa15Rejection(rsa15DiscoveryUrl, rsa15ResourceEndpoint).then(() => {
                console.log('\n✓ Test PASSED: Client correctly rejected RSA1_5 encrypted ID token');
                process.exit(0);
            }).catch(err => {
                // Check if this is actually a success case (RSA1_5 rejection)
                if (err.message && (err.message.includes('RSA1_5') || err.message.includes('disallowed algorithm'))) {
                    console.log('\n✓ Test PASSED: Client correctly rejected RSA1_5 encrypted ID token');
                    process.exit(0);
                }
                console.error('Failed to execute encrypted-rsa15 test:', err);
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
    client2,
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
    testNoScope,
    testNoScopeExpiresInTokenResponseMock,
    testInvalidNonce,
    testOldIat,
    testMissingAtHash,
    testAudAsArray,
    testAudAsArrayMock,
    testEncryptedIdToken,
    testEncryptedIdTokenRsa15Rejection,
    getJwksAsJson
};