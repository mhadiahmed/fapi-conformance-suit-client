import { testRefreshTokenFlow, main } from './index';
import { FAPIClient } from './fapiClient';

const args = process.argv.slice(2);

const discoveryUrl = args[0] || process.env.DISCOVERY_URL;
const resourceEndpoint = args[1] || process.env.RESOURCE_ENDPOINT;

if (!discoveryUrl || !resourceEndpoint) {
    console.error('Missing required parameters. Usage:');
    console.error('ts-node src/run-refresh-token-test.ts <discoveryUrl> <resourceEndpoint>');
    console.error('Alternatively, set DISCOVERY_URL and RESOURCE_ENDPOINT environment variables.');
    process.exit(1);
}

// Type assertions after validation
const validatedDiscoveryUrl: string = discoveryUrl;
const validatedResourceEndpoint: string = resourceEndpoint;

console.log('=== FAPI1 Advanced Final Client Refresh Token Test Runner ===');
console.log('Discovery URL:', validatedDiscoveryUrl);
console.log('Resource Endpoint:', validatedResourceEndpoint);

async function runTest(): Promise<void> {
    try {
        // Initialize client properly
        const client = await main();
        if (!client) {
            throw new Error('Failed to get initialized client');
        }
        
        // Run the refresh token test with validated URLs
        const result = await testRefreshTokenFlow(validatedDiscoveryUrl, validatedResourceEndpoint);
        console.log('Test result:', result);
        console.log('Test completed successfully');
    } catch (error) {
        console.error('\n=== Test Failed ===');
        console.error('Error:', error instanceof Error ? error.message : String(error));
        process.exit(1);
    }
}

runTest().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
});
