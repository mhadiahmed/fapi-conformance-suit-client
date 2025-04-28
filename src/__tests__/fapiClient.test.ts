import axios from 'axios';
import { FAPIClient, FAPIClientConfig } from '../fapiClient';
import * as path from 'path';

jest.mock('axios');

describe('FAPI Token Endpoint Tests', () => {
    const config: FAPIClientConfig = {
        clientId: '2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
        clientSecret: 'ae149792-aeb9-40c6-9498-5f64d65262b1',
        tokenEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/ais-corporate/token',
        certPath: path.join(__dirname, '../certs/client.crt'),
        keyPath: path.join(__dirname, '../certs/client.key'),
        caCertPath: path.join(__dirname, '../certs/ca.crt')
    };
    
    const requestedScopes = ['openid', 'payments'];
    let fapiClient: FAPIClient;
    
    beforeEach(() => {
        fapiClient = new FAPIClient(config);
        fapiClient.setRequestedScopes(requestedScopes);
        jest.clearAllMocks();
    });

    test('should handle token response without scopes and expires_in', async () => {
        // Mock the token response without scopes and expires_in
        const mockTokenResponse = {
            data: {
                access_token: 'mock_access_token',
                token_type: 'Bearer'
                // Note: No scope or expires_in fields
            }
        };

        (axios as jest.MockedFunction<typeof axios>).mockResolvedValueOnce(mockTokenResponse);

        // Act
        const response = await fapiClient.getClientCredentialsToken();

        // Assert
        expect(response.access_token).toBeDefined();
        expect(response.token_type).toBe('Bearer');
        expect(response.expires_in).toBeUndefined();
        expect(response.scope).toBe(requestedScopes.join(' '));
        
        // Verify the request was made with correct parameters
        expect(axios).toHaveBeenCalledWith(expect.objectContaining({
            method: 'post',
            url: config.tokenEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': expect.stringContaining('Basic ')
            },
            data: expect.any(URLSearchParams),
            httpsAgent: expect.any(Object)
        }));

        // Verify the effective scopes
        const effectiveScopes = fapiClient.getEffectiveScopes(response);
        expect(effectiveScopes).toEqual(requestedScopes);
    });
});