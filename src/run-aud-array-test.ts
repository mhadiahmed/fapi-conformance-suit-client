import { FAPIClient } from './fapiClient';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// The callback URL provided by the FAPI test (from command line argument)
const callbackUrl = process.argv[2];

if (!callbackUrl) {
    console.error('Please provide the callback URL as a command line argument');
    console.error('Example: ts-node src/run-aud-array-test.ts "https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate/callback#state=..."');
    process.exit(1);
}

// Simple function to analyze token from URL
function analyzeToken(url: string) {
    console.log('Original URL:', url);
    
    // Handle escaped characters in the URL
    const unescapedUrl = url.replace(/\\\=/g, '=').replace(/\\\&/g, '&').replace(/\\\#/g, '#');
    console.log('Unescaped URL:', unescapedUrl);
    
    const hashIndex = unescapedUrl.indexOf('#');
    if (hashIndex === -1) {
        throw new Error('No hash fragment found in URL');
    }
    
    const fragment = unescapedUrl.substring(hashIndex + 1);
    console.log('Fragment:', fragment);
    
    const params = new URLSearchParams(fragment);
    const idToken = params.get('id_token');
    
    if (!idToken) {
        throw new Error('No ID token found in URL fragment');
    }
    
    console.log('ID token found:', idToken.substring(0, 20) + '...');
    
    const [headerB64, payloadB64, signatureB64] = idToken.split('.');
    if (!payloadB64) {
        throw new Error('Invalid ID token format - cannot parse payload');
    }
    
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    
    console.log('ID Token payload:', JSON.stringify(payload, null, 2));
    
    // Check audience format
    const isAudArray = Array.isArray(payload.aud);
    console.log(`Audience is an ${isAudArray ? 'array' : 'string'}: ${JSON.stringify(payload.aud)}`);
    
    return {
        idToken,
        payload,
        isAudArray
    };
}

// Manual audience validation 
function validateAudience(payload: any, clientId: string): { valid: boolean, reason?: string } {
    console.log(`Validating audience against client ID: ${clientId}`);
    
    if (!payload.aud) {
        return { valid: false, reason: 'Missing audience (aud) in ID token' };
    }
    
    if (Array.isArray(payload.aud)) {
        console.log('Audience is an array with values:', payload.aud);
        
        // Check if our client ID is in the audience array
        if (payload.aud.includes(clientId)) {
            console.log(`✓ Client ID "${clientId}" found in audience array`);
            return { valid: true };
        } else {
            console.log(`✗ Client ID "${clientId}" NOT found in audience array`);
            return { 
                valid: false, 
                reason: `Client ID not found in audience array. Expected: ${clientId}, Got: ${JSON.stringify(payload.aud)}`
            };
        }
    } else {
        console.log('Audience is a string:', payload.aud);
        
        // Check if our client ID matches the audience string
        if (payload.aud === clientId) {
            console.log(`✓ Client ID "${clientId}" matches audience string`);
            return { valid: true };
        } else {
            console.log(`✗ Client ID "${clientId}" does NOT match audience string`);
            return { 
                valid: false, 
                reason: `Client ID does not match audience. Expected: ${clientId}, Got: ${payload.aud}`
            };
        }
    }
}

async function runTest() {
    try {
        console.log('Starting audience-as-array test...');
        
        // Analyze the token in the URL
        const { idToken, payload, isAudArray } = analyzeToken(callbackUrl);
        
        // Create FAPI client with configuration
        const clientId = process.env.CLIENT_ID || '2d4c95a7-6dc3-4416-ab1c-ea44501635aa';
        const client = new FAPIClient({
            clientId: clientId,
            clientSecret: process.env.CLIENT_SECRET || 'ae149792-aeb9-40c6-9498-5f64d65262b1',
            tokenEndpoint: process.env.TOKEN_ENDPOINT || 'https://localhost.emobix.co.uk:8444/test-mtls/a/seentarbi-ais-corporate/token',
            parEndpoint: process.env.PAR_ENDPOINT || 'https://localhost.emobix.co.uk:8444/test-mtls/a/seentarbi-ais-corporate/par',
            issuer: process.env.ISSUER || 'https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate',
            redirectUri: process.env.REDIRECT_URI || 'https://localhost.emobix.co.uk:8443/test/a/seentarbi-ais-corporate/callback'
        });
        
        console.log('Validating ID token audience...');
        
        // Manually validate the audience
        const audValidation = validateAudience(payload, clientId);
        
        const validationResult = {
            success: audValidation.valid,
            message: audValidation.valid 
                ? `Successfully validated ID token with audience as ${isAudArray ? 'array' : 'string'}`
                : (audValidation.reason || 'Unknown validation error'),
            audience: payload.aud,
            clientId
        };
        
        console.log('Test completed!');
        console.log('Result:', JSON.stringify(validationResult, null, 2));
        
        return validationResult;
    } catch (error) {
        console.error('Error running test:', error);
        process.exit(1);
    }
}

// Run the test
runTest().then(() => {
    console.log('Test execution completed.');
}); 