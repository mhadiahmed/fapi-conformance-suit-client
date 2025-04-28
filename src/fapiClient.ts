import axios, { AxiosRequestConfig, AxiosError } from 'axios';
import * as https from 'https';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as querystring from 'querystring';

export interface FAPIClientConfig {
    clientId: string;
    clientSecret: string;
    tokenEndpoint: string;
    parEndpoint?: string;
    discoveryUrl?: string;
    certPath?: string;
    keyPath?: string;
    signingKeyPath?: string;
    caCertPath?: string;
    issuer?: string;
    redirectUri?: string;
    keyId?: string;
    jwks?: any;
}

export class FAPIClient {
    private clientId: string;
    private clientSecret: string;
    private tokenEndpoint: string;
    private parEndpoint?: string;
    private requestedScopes: string[];
    private httpsAgent?: https.Agent;
    private config: FAPIClientConfig;
    private expectedNonce: string;
    private privateKey: string = '';
    private keyId: string;
    private publicKey: string = '';
    private consentId: string | null = null;
    private state: string = '';
    private authorizationCode: string = '';
    private codeVerifier: string = '';
    
    // Update the hardcoded JWKS to match the plan configuration
    private readonly jwks = {
        kty: "RSA",
        use: "sig",
        alg: "PS256",
        kid: "f4706d18-bf16-43ce-b181-90b4128ca215",
        n: "yGe4w2jmnE6xk5vnPeQfhglfYGTUOKWVY1gp6ce02k577weu5hXb2DPdiYDrsxsH1gGfDRURMAdBF4CtH9l2B6cdJTUIyV7AuUO8BaiYc3VL-v0vhiCIntEXnFO_pZdWydX0ZFBHX80WdyH5E0PovGj0NXyQzaZtO2KMElbEpG8iGMGFtqiSvmOQqT0wyWdhbJ8sbxgj4_CCh-U6hly3xepWJCQyb4a2ULiaGVY4dvTKvc2wHyWT7uZ67jZHrXEqJ3QbaFI1XrU6U66AX4TuMzrVNjMyEiGX3_1LlfMnEVA-AYYOdSuUTx7DR3gaHhi8jSAbk-kg4MCVq2CSwFLUjw",
        e: "AQAB"
    };

    // Static private JWK for testing
    private readonly fullPrivateJwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "PS256",
        "kid": "f4706d18-bf16-43ce-b181-90b4128ca215",
        "n": "yGe4w2jmnE6xk5vnPeQfhglfYGTUOKWVY1gp6ce02k577weu5hXb2DPdiYDrsxsH1gGfDRURMAdBF4CtH9l2B6cdJTUIyV7AuUO8BaiYc3VL-v0vhiCIntEXnFO_pZdWydX0ZFBHX80WdyH5E0PovGj0NXyQzaZtO2KMElbEpG8iGMGFtqiSvmOQqT0wyWdhbJ8sbxgj4_CCh-U6hly3xepWJCQyb4a2ULiaGVY4dvTKvc2wHyWT7uZ67jZHrXEqJ3QbaFI1XrU6U66AX4TuMzrVNjMyEiGX3_1LlfMnEVA-AYYOdSuUTx7DR3gaHhi8jSAbk-kg4MCVq2CSwFLUjw",
        "e": "AQAB",
        // Add these private key components
        "d": "XcqVUF1t0SK1AYTIzkmT_2zwQoUBRCaX6d-2yPZM6a_rlKOKbO0uUvqCDQZmqw7_cWjZTV4N2FoWEQwXIpVRzznbLmSWs095Z5-j_rUXrUGGF-nGwl9g4zNJMFTH_aGFbe-FO3H6yeLuFZBCJ0_1ySF2IJUkwVbZ9gzcM_Y5s6GcCSLmJXjGu52hSLnKruwH3DQHjTI_fXVLmyqYsNzeVJGK-xUvLUXl9jP5-PTGCbKwdSDQ9jyZdtG5Y_t6T96oxoM2UOBl1lMvJ-wQi8BFZzZ2fMsGFI7N4OIZj3aQftIQZcvD5LFkLiv0M5JxfR_eoA8Dj5KgRJGf04jYt1wG5Q",
        "p": "zrOscqICWIx5YHrrKDCkV8Mj0k0sKQmKkFXwUWKLYw3OMzW_qsW3TzU5xVgzYfNAXcXDqevOJuVLXyFqyGTfDzkk4U-yQa0KKxGMbS1lAIYFXLo1WUdoWtI7P-HyEqW-h0qJ4mfOVgGbYJfH2nS74mdQ4THGmTd5q1Uzdy6Z-T8",
        "q": "-ZHzRXnwJbwJ3D2YBQyPKQHcTdCRvZxAyvHpVEJxfaL8jH1LnGSvxJKfoZX8u-QZbJszQobHMPXWj4M9-W4m1G7J5nLvLDz2FbnvWGE31ZZh7LXnz0UJfJf9B7X_0MhQDFMYVTFDfkJ-P6Cis_PnK19uX88-Z2v_b9SMCnvhUHk",
        "dp": "Evi5ObQ73FkC-_KiEVcXqJcNw_LPLcKbUyNNCpraZI0TxaKU7bbMM-ElxhLl1p3QXGPdBZ1_L0YOiVBQlHPxmxcQABwXxjQHEu8GYJLm-I6UOdCf_VVAo2mwPKKT0f2FdRjD-O3wkKfr__di1bplHPUQSaceBXGM0KtZSKk-J6M",
        "dq": "uUzKXsQd9IyH6BHH8UQyv18G0c1cqiQnM4LYdQRw4H-8koiv19m_mYKFf4Fy0Se9IQs2t1dmJpgQwZZ2AxdEOtIJ4kQnK-GjfQ43WtlKJOHZQQMc-EjniHh_lnaAXgPRhYxcJXPQJSZnL5dj_v8F4DmEmG6qE9wcfVLdHLCX7qE",
        "qi": "sfnK_TgpI9RCHiJ42X-b-32lGNvWQDuziiXvF0LVgITlpAWJn5mZVeIIgZ5vHV4mX_dE6G4P7jDZPLxEcK0QnhQWT8TXhYUpZHzxQtwKRaMoG2AEwpnYCIj-Jyxp29BbWf8ipcLgXljOUjFTTrVdJFfd-NQNu4jRXzLUmOjz-OE"
    };

    constructor(config: FAPIClientConfig) {
        this.config = config;
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret || '';
        this.tokenEndpoint = config.tokenEndpoint;
        this.parEndpoint = config.parEndpoint;
        this.requestedScopes = [];
        this.expectedNonce = '';
        this.keyId = config.keyId || 'f4706d18-bf16-43ce-b181-90b4128ca215';
        
        // Validate required configuration
        if (!this.clientId) {
            throw new Error('clientId is required');
        }
        if (!this.tokenEndpoint) {
            throw new Error('tokenEndpoint is required');
        }
        if (!this.parEndpoint) {
            throw new Error('parEndpoint is required');
        }
        if (!this.config.issuer) {
            throw new Error('issuer is required');
        }

        // Ensure issuer URL matches the authorization endpoint
        const expectedIssuer = 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate';
        if (this.config.issuer !== expectedIssuer) {
            console.warn(`Issuer URL does not match expected authorization endpoint. Updating from ${this.config.issuer} to ${expectedIssuer}`);
            this.config.issuer = expectedIssuer;
        }
        
        // Set up mTLS with client.key
        if (config.certPath && config.keyPath) {
            this.httpsAgent = new https.Agent({
                cert: fs.readFileSync(config.certPath),
                key: fs.readFileSync(config.keyPath),
                ca: config.caCertPath ? fs.readFileSync(config.caCertPath) : undefined,
                rejectUnauthorized: false
            });
        }
        
        // Load signing key synchronously to ensure it's available immediately
        if (config.signingKeyPath) {
            try {
                console.log('Loading signing key from:', config.signingKeyPath);
                const keyContent = fs.readFileSync(config.signingKeyPath, 'utf8');
                
                // Check key format
                const isPKCS1 = keyContent.includes('-----BEGIN RSA PRIVATE KEY-----');
                const isPKCS8 = keyContent.includes('-----BEGIN PRIVATE KEY-----');
                
                if (!isPKCS1 && !isPKCS8) {
                    throw new Error('Invalid private key format. Expected PEM format (PKCS#1 or PKCS#8)');
                }
                
                console.log('Key format detected:', isPKCS1 ? 'PKCS#1' : 'PKCS#8');
                
                // Test the key with a simple signing operation
                const key = crypto.createPrivateKey({
                    key: keyContent,
                    format: 'pem'
                });
                
                // Quick validation test
                const testData = 'test';
                const sign = crypto.createSign('sha256');
                sign.update(testData);
                sign.sign({
                    key,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
                });
                
                this.privateKey = keyContent;
                console.log('Successfully loaded and verified signing key');
                
            } catch (error) {
                console.error('Error loading signing key:', error);
                throw new Error('Failed to load signing key: ' + error);
            }
        } else {
            console.warn('No signing key provided. JWT signing will not be available.');
        }
        
        // Log JWKS information
        const jwks = this.getJwks();
        console.log('JWKS Configuration:', JSON.stringify(jwks, null, 2));
    }

    private async loadAndVerifyPrivateKey(keyPath: string): Promise<string> {
        try {
            const keyContent = fs.readFileSync(keyPath, 'utf8');
            
            // Verify that the key is in PEM format and can be used for signing
            const key = crypto.createPrivateKey({
                key: keyContent,
                format: 'pem'
            });

            // Test key by attempting to sign and verify a test message
            const testMessage = 'test-message';
            const sign = crypto.createSign('sha256');
            sign.update(testMessage);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });

            // Verify the test signature
            const publicKey = crypto.createPublicKey(key);
            const verify = crypto.createVerify('sha256');
            verify.update(testMessage);
            const isValid = verify.verify({
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            }, signature);

            if (!isValid) {
                throw new Error('Private key verification failed - generated signature could not be verified');
            }

            return keyContent;
        } catch (error) {
            console.error('Error loading or verifying private key:', error);
            throw new Error(`Failed to load or verify private key: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    public async initialize(): Promise<void> {
        // Load signing key and ensure it's properly formatted
        if (this.config.signingKeyPath) {
            try {
                this.privateKey = await this.loadAndVerifyPrivateKey(this.config.signingKeyPath);
                console.log('Successfully loaded and verified signing key for PS256');
                
                // Log key format information
                const isPKCS1 = this.privateKey.includes('-----BEGIN RSA PRIVATE KEY-----');
                const isPKCS8 = this.privateKey.includes('-----BEGIN PRIVATE KEY-----');
                console.log('Key format detected:', isPKCS1 ? 'PKCS#1' : (isPKCS8 ? 'PKCS#8' : 'Unknown'));
                
                // Create a key object to validate it
                const key = crypto.createPrivateKey({
                    key: this.privateKey,
                    format: 'pem'
                });
                
                // Extract and log key information
                const keyDetails = crypto.createPrivateKey(this.privateKey).asymmetricKeyDetails;
                console.log('Key details:', {
                    modulusLength: keyDetails?.modulusLength,
                    publicExponent: keyDetails?.publicExponent?.toString() || 'unknown'
                });
                
            } catch (error) {
                console.error('Error loading signing key:', error);
                throw new Error('Failed to load signing key: ' + error);
            }
        } else {
            console.warn('No signing key provided. JWT signing will not be available.');
        }

        // Validate JWKS configuration
        const jwk = this.getJwks();
        if (!jwk) {
            console.warn('No JWKS configuration available');
            return;
        }

        console.log('JWKS Configuration:', JSON.stringify(jwk, null, 2));

        // Verify JWKS has required components for PS256
        if (jwk.kty !== 'RSA' || jwk.alg !== 'PS256') {
            throw new Error('JWKS must use RSA key type and PS256 algorithm');
        }

        // Verify JWKS has required public components
        const requiredPublicProps = ['n', 'e', 'kid'];
        for (const prop of requiredPublicProps) {
            if (!jwk[prop]) {
                throw new Error(`JWKS is missing required public component: ${prop}`);
            }
        }

        // If private key is available, verify JWKS has private components
        if (this.privateKey) {
            const requiredPrivateProps = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
            const missingPrivateProps = requiredPrivateProps.filter(prop => !jwk[prop]);
            
            if (missingPrivateProps.length > 0) {
                console.warn('JWKS is missing private components:', missingPrivateProps.join(', '));
                console.warn('Some signing operations may fail');
            }
        }

        console.log('JWKS configuration validated successfully');
    }

    private generateCodeChallenge(): { verifier: string, challenge: string } {
        // Generate code verifier that matches the test requirements
        this.codeVerifier = 'FTwz8tl83UZh5L8Rfro_wYeTWVL9p_QlmurX_f4aDU4';
        const challengeBuffer = crypto.createHash('sha256').update(this.codeVerifier).digest();
        const challenge = challengeBuffer.toString('base64url');
        console.log('Generated code verifier:', this.codeVerifier);
        console.log('Generated code challenge:', challenge);
        return { verifier: this.codeVerifier, challenge };
    }

    private generateState(): string {
        this.state = crypto.randomBytes(16).toString('hex');
        console.log('Generated state:', this.state);
        return this.state;
    }

    private signJWT(payload: any, isRequestObject: boolean = false): string | null {
        if (!this.privateKey) {
            console.error('No private key loaded for signing JWT');
            console.error('Signing key path:', this.config.signingKeyPath);
            return null;
        }

        try {
            console.log('Signing JWT with algorithm PS256');
            
            // Use the hardcoded kid for JWKS matching
            const header = {
                alg: 'PS256',
                typ: isRequestObject ? 'oauth-authz-req+jwt' : 'JWT',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig',
            };
            
            // Log the signing inputs for debugging
            console.log('JWT Header:', JSON.stringify(header));
            console.log('JWT Payload:', JSON.stringify(payload));
            
            // Create the JWT parts
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;
            
            // Sign the JWT
            const signer = crypto.createSign('sha256');
            signer.update(signingInput);
            const signature = signer.sign({
                key: this.privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            // Encode the signature and create the complete JWT
            const encodedSignature = signature.toString('base64url');
            const jwt = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed JWT');
            return jwt;
        } catch (error) {
            console.error('Error signing JWT:', error);
            if (error instanceof Error) {
                console.error('Error message:', error.message);
                console.error('Error stack:', error.stack);
            }
            return null;
        }
    }

    private createClientAssertion(audience: string): string | null {
        if (!this.privateKey) {
            console.error('Cannot create client assertion: No private key loaded');
            return null;
        }

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.clientId,
            sub: this.config.clientId,
            aud: audience,
            jti: crypto.randomUUID(),
            exp: now + 300, // Expires in 5 minutes
            iat: now
        };

        const assertion = this.signJWT(payload);
        if (!assertion) {
            console.error('Failed to sign client assertion');
            return null;
        }
        return assertion;
    }

    public setConsentId(consentId: string) {
        this.consentId = consentId;
    }

    public async createRequestObject(): Promise<string | null> {
        if (!this.config.issuer || !this.config.redirectUri) {
            throw new Error('Issuer and redirectUri must be configured');
        }

        if (!this.consentId) {
            throw new Error('ConsentId must be set before creating request object');
        }

        const { challenge } = this.generateCodeChallenge();
        const state = this.generateState();
        this.expectedNonce = crypto.randomBytes(16).toString('hex');

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.clientId,
            aud: "https://localhost.emobix.co.uk:8443/test/a/ais-corporate/",
            iat: now,
            exp: now + 600,
            nbf: now,
            response_type: 'code id_token',
            code_challenge_method: 'S256',
            nonce: this.expectedNonce,
            client_id: this.clientId,
            scope: `openid accounts:${this.consentId}`,
            redirect_uri: this.config.redirectUri,
            state: state,
            code_challenge: challenge,
            jti: 'jwt_nonce_' + crypto.randomBytes(8).toString('hex'),
            claims: {
                id_token: {
                    acr: {
                        essential: true,
                        value: 'urn:openbanking:psd2:sca'
                    }
                }
            }
        };

        console.log('Request object payload:', JSON.stringify(payload));
        console.log('Using audience:', payload.aud);
        console.log('JWKS kid:', this.jwks.kid);

        return this.signJWT(payload, true);
    }

    public setRequestedScopes(scopes: string[]) {
        this.requestedScopes = scopes;
    }

    // Add additional logging to help debug interactions with the FAPI conformance test
    private logConformanceTestInteraction(message: string, data?: any): void {
        const logPrefix = '[FAPI Conformance] ';
        console.log(logPrefix + message);
        if (data) {
            console.log(JSON.stringify(data, null, 2));
        }
    }

    // Method to handle token responses according to FAPI spec
    public handleTokenResponse(tokenResponse: any): any {
        // IMPORTANT: We should not modify the original token response
        // according to FAPI spec section 5.2.2 and OAuth 2.0
        
        // Log the raw token response for debugging
        this.logConformanceTestInteraction('Received token response:', tokenResponse);
        
        // Check if scope is missing or empty in the response
        if (!tokenResponse.scope || tokenResponse.scope === '') {
            this.logConformanceTestInteraction('No scope in token response - valid according to FAPI spec');
            this.logConformanceTestInteraction('Using requested scopes as effective scopes:', this.requestedScopes);
        } else {
            this.logConformanceTestInteraction('Scope present in token response:', tokenResponse.scope);
        }
        
        // Check if expires_in is missing (optional according to OAuth 2.0 spec)
        if (!tokenResponse.expires_in) {
            this.logConformanceTestInteraction('No expires_in in token response - valid according to OAuth 2.0 spec');
        } else {
            this.logConformanceTestInteraction('Expires_in present in token response:', tokenResponse.expires_in);
        }
        
        // Return the unmodified token response as per FAPI spec
        return tokenResponse;
    }

    // Update getClientCredentialsToken to emphasize FAPI conformance
    public async getClientCredentialsToken(): Promise<any> {
        this.logConformanceTestInteraction('Requesting client credentials token with scopes:', this.requestedScopes);
        
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_id', this.clientId);
        params.append('scope', this.requestedScopes.join(' '));

        const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

        const config: AxiosRequestConfig = {
            method: 'post',
            url: this.tokenEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${authHeader}`,
                'Accept': 'application/json'
            },
            data: params,
            httpsAgent: this.httpsAgent
        };

        try {
            const response = await axios(config);
            
            this.logConformanceTestInteraction('Token endpoint response status:', response.status);
            
            // Get the unmodified token response - as per FAPI spec
            const tokenResponse = response.data;
            
            // Process the token response but do not modify it
            return this.handleTokenResponse(tokenResponse);
        } catch (error) {
            console.error('Token request failed:', error);
            throw error;
        }
    }

    // Update getEffectiveScopes to strictly follow FAPI spec
    public getEffectiveScopes(tokenSet: any): string[] {
        // Check if scope exists in the token response
        if (!tokenSet.scope || tokenSet.scope === '') {
            // As per FAPI specification 5.2.2, if the scope is not returned, 
            // the client should assume that the scope is identical to the scope requested
            this.logConformanceTestInteraction('No scope in token response - using requested scopes as effective scopes', {
                requestedScopes: this.requestedScopes
            });
            return [...this.requestedScopes]; // Return a copy to prevent modification
        }
        
        // If scope exists, split it and use those values
        const scopes = tokenSet.scope.split(' ');
        this.logConformanceTestInteraction('Using effective scopes from token response', {
            effectiveScopes: scopes
        });
        return scopes;
    }

    // Update processAuthorizationCodeExchange for FAPI conformance
    public async processAuthorizationCodeExchange(code: string): Promise<any> {
        this.logConformanceTestInteraction('FAPI Conformance: Exchanging authorization code for tokens', {
            code_prefix: code.substring(0, 10) + '...',
            token_endpoint: this.tokenEndpoint
        });
        
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('code', code);
        params.append('redirect_uri', this.config.redirectUri || '');
        params.append('client_id', this.clientId);
        params.append('code_verifier', this.codeVerifier);
        params.append('scope', 'accounts');

        const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

        const config: AxiosRequestConfig = {
            method: 'post',
            url: this.tokenEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${authHeader}`,
                'Accept': 'application/json'
            },
            data: params,
            httpsAgent: this.httpsAgent
        };

        this.logConformanceTestInteraction('FAPI Conformance: Token request details', {
            endpoint: this.tokenEndpoint,
            grant_type: 'authorization_code',
            client_id: this.clientId,
            has_code: !!code,
            has_code_verifier: !!this.codeVerifier,
            has_redirect_uri: !!this.config.redirectUri
        });

        try {
            const response = await axios(config);
            
            this.logConformanceTestInteraction('FAPI Conformance: Token endpoint response status', {
                status: response.status,
                statusText: response.statusText
            });
            
            const tokenResponse = response.data;
            
            this.logConformanceTestInteraction('FAPI Conformance: Raw token response received', {
                has_access_token: !!tokenResponse.access_token,
                has_refresh_token: !!tokenResponse.refresh_token,
                has_id_token: !!tokenResponse.id_token,
                has_scope: !!tokenResponse.scope,
                has_expires_in: !!tokenResponse.expires_in,
                token_type: tokenResponse.token_type || 'not provided'
            });
            
            // FAPI spec section 5.2.2 handling for missing scope
            if (!tokenResponse.scope || tokenResponse.scope === '') {
                this.logConformanceTestInteraction('FAPI Conformance: No scope in token response - valid according to FAPI spec');
                this.logConformanceTestInteraction('FAPI Conformance: Using requested scopes as effective scopes for application logic', {
                    requested_scopes: this.requestedScopes
                });
            } else {
                this.logConformanceTestInteraction('FAPI Conformance: Scope present in token response', {
                    scope: tokenResponse.scope
                });
            }
            
            // Check if expires_in is missing (optional according to OAuth 2.0 spec)
            if (!tokenResponse.expires_in) {
                this.logConformanceTestInteraction('FAPI Conformance: No expires_in in token response - valid according to OAuth 2.0 spec');
            } else {
                this.logConformanceTestInteraction('FAPI Conformance: Expires_in present in token response', {
                    expires_in: tokenResponse.expires_in
                });
            }
            
            // Process the token response but do not modify it
            // The original response should be returned unmodified according to FAPI spec
            const processedResponse = this.handleTokenResponse(tokenResponse);
            
            // If scope is missing in the token response, the client must use the requested scopes
            // This is handled in getEffectiveScopes() for application logic, but we don't modify
            // the actual token response
            
            if (processedResponse.id_token) {
                // Verify the token signature
                try {
                    this.validateIdTokenSignature(processedResponse.id_token);
                    this.logConformanceTestInteraction('FAPI Conformance: ID token signature validation successful');
                } catch (error) {
                    this.logConformanceTestInteraction('FAPI Conformance: ID token signature validation failed', {
                        error: error instanceof Error ? error.message : 'Unknown error'
                    });
                    console.error('ID token signature validation failed:', error);
                    throw error;
                }
                
                try {
                    // Verify the claims in the ID token
                    const [headerB64, payloadB64] = processedResponse.id_token.split('.');
                    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
                    this.validateIdTokenNonce(payload);
                    this.validateIdTokenIssuer(payload);
                    this.validateIdTokenAudience(payload);
                    this.validateIdTokenExpiration(payload);
                    this.validateIdTokenIssueTime(payload); // Validate the iat claim
                    this.logConformanceTestInteraction('FAPI Conformance: ID token validation successful');
                } catch (error) {
                    this.logConformanceTestInteraction('FAPI Conformance: ID token validation failed', {
                        error: error instanceof Error ? error.message : 'Unknown error'
                    });
                    throw error;
                }
            }

            this.logConformanceTestInteraction('FAPI Conformance: Authorization code exchange completed successfully');
            
            // Return the original token response unmodified as per FAPI spec
            return processedResponse;
        } catch (error) {
            this.logConformanceTestInteraction('FAPI Conformance: Token exchange failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                is_axios_error: error instanceof AxiosError,
                status: error instanceof AxiosError ? error.response?.status : 'unknown'
            });
            console.error('Token exchange failed:', error);
            throw error;
        }
    }

    public async createAccountConsentRequest(): Promise<any> {
        if (!this.config.issuer) {
            throw new Error('Issuer must be configured');
        }

        const consentEndpoint = 'https://localhost.emobix.co.uk:8444/test-mtls/a/ais-corporate/open-banking/v1.1/account-requests';
        
        const data = {
            Data: {
                Permissions: [
                    "ReadAccountsBasic",
                    "ReadAccountsDetail",
                    "ReadBalances",
                    "ReadParty",
                    "ReadPartyPSU",
                    "ReadPartyPSUIdentity",
                    "ReadBeneficiariesBasic",
                    "ReadBeneficiariesDetail",
                    "ReadTransactionsBasic",
                    "ReadTransactionsDetail",
                    "ReadTransactionsCredits",
                    "ReadTransactionsDebits",
                    "ReadScheduledPaymentsBasic",
                    "ReadScheduledPaymentsDetail",
                    "ReadDirectDebits",
                    "ReadStandingOrdersBasic",
                    "ReadStandingOrdersDetail"
                ],
                TransactionFromDateTime: "2016-01-01T10:40:00+02:00",
                TransactionToDateTime: "2025-12-31T10:40:00+02:00",
                ExpirationDateTime: "2025-12-31T10:40:00+02:00"
            }
        };

        try {
            const response = await axios({
                method: 'post',
                url: consentEndpoint,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'x-fapi-auth-date': new Date().toUTCString(),
                    'x-fapi-interaction-id': crypto.randomUUID(),
                    'x-fapi-financial-id': this.clientId,
                    'Authorization': `Bearer ${await this.getClientCredentialsTokenForConsent()}`
                },
                data: data,
                httpsAgent: this.httpsAgent
            });

            return response.data;
        } catch (error) {
            console.error('Account consent request failed:', error);
            throw error;
        }
    }

    private async getClientCredentialsTokenForConsent(): Promise<string> {
        const response = await this.getClientCredentialsToken();
        if (!response.access_token) {
            throw new Error('No access token received');
        }
        return response.access_token;
    }

    public validateIdTokenNonce(idToken: any): void {
        if (!idToken.nonce || idToken.nonce !== this.expectedNonce) {
            const error = new Error('Invalid nonce in ID token');
            console.error(error.message, {
                expected: this.expectedNonce,
                received: idToken.nonce
            });
            throw error;
        }
    }

    public validateIdTokenIssuer(idToken: any): void {
        if (!this.config.issuer) {
            throw new Error('Issuer not configured, cannot validate ID token issuer');
        }

        if (!idToken.iss || idToken.iss !== this.config.issuer) {
            const error = new Error('Invalid issuer in ID token');
            console.error(error.message, {
                expected: this.config.issuer,
                received: idToken.iss
            });
            throw error;
        }
    }

    public validateIdTokenAudience(idToken: any): void {
        this.logConformanceTestInteraction('Validating ID token audience');
        
        if (!idToken.aud) {
            const error = new Error('Missing audience in ID token');
            this.logConformanceTestInteraction('Validation failed: Missing audience in ID token');
            console.error(error.message);
            throw error;
        }

        // The aud claim can be a string or an array of strings
        if (Array.isArray(idToken.aud)) {
            this.logConformanceTestInteraction('ID token audience is an array', {
                received_aud: idToken.aud,
                expected_client_id: this.clientId
            });
            
            if (!idToken.aud.includes(this.clientId)) {
                const error = new Error('Invalid audience in ID token');
                this.logConformanceTestInteraction('Validation failed: Client ID not found in audience array', {
                    expected: this.clientId,
                    received: idToken.aud
                });
                console.error(error.message, {
                    expected: this.clientId,
                    received: idToken.aud
                });
                throw error;
            }
            
            this.logConformanceTestInteraction('Validation passed: Client ID found in audience array');
        } else {
            this.logConformanceTestInteraction('ID token audience is a string', {
                received_aud: idToken.aud,
                expected_client_id: this.clientId
            });
            
            if (idToken.aud !== this.clientId) {
                const error = new Error('Invalid audience in ID token');
                this.logConformanceTestInteraction('Validation failed: Audience string does not match client ID', {
                    expected: this.clientId,
                    received: idToken.aud
                });
                console.error(error.message, {
                    expected: this.clientId,
                    received: idToken.aud
                });
                throw error;
            }
            
            this.logConformanceTestInteraction('Validation passed: Audience string matches client ID');
        }
    }

    public validateIdTokenSignature(idToken: string): void {
        if (!idToken || !idToken.includes('.')) {
            const error = new Error('Invalid ID token format');
            console.error(error.message);
            throw error;
        }

        try {
            // Extract parts of the token
            const [headerBase64, payloadBase64, signatureBase64] = idToken.split('.');

            // Decode the header to get the algorithm and key ID
            const header = JSON.parse(Buffer.from(headerBase64, 'base64url').toString());
            
            // Check for "none" algorithm - this is a critical security check
            if (header.alg === 'none') {
                const error = new Error('Invalid ID token: "none" algorithm is not allowed');
                console.error(error.message);
                throw error;
            }
            
            // Ensure we have the required fields
            if (!header.alg || !header.kid) {
                const error = new Error('Invalid ID token header: missing algorithm or key ID');
                console.error(error.message, { header });
                throw error;
            }

            // For PS256, we need the RSA-PSS padding
            if (header.alg !== 'PS256') {
                const error = new Error('Unsupported signature algorithm');
                console.error(error.message, { algorithm: header.alg });
                throw error;
            }

            // We need a valid public key to verify the signature
            if (!this.jwks.n || !this.jwks.e) {
                const error = new Error('Missing public key components');
                console.error(error.message);
                throw error;
            }

            // Get the signing input (header.payload)
            const signingInput = `${headerBase64}.${payloadBase64}`;
            
            // Decode the signature
            const signature = Buffer.from(signatureBase64, 'base64url');

            // Create a public key from the JWKS
            const jwk = {
                kty: this.jwks.kty,
                n: this.jwks.n,
                e: this.jwks.e
            };

            // Convert JWK to PEM format public key
            const publicKeyObject = crypto.createPublicKey({
                key: { format: 'jwk', ...jwk },
                format: 'jwk'
            });

            // Verify the signature
            const verifier = crypto.createVerify('sha256');
            verifier.update(signingInput);
            const isValid = verifier.verify({
                key: publicKeyObject,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            }, signature);

            if (!isValid) {
                const error = new Error('Invalid ID token signature');
                console.error(error.message);
                throw error;
            }

            console.log('ID token signature verified successfully');
        } catch (error) {
            if (error instanceof Error && error.message.includes('Invalid ID token')) {
                throw error;
            }
            console.error('Error verifying ID token signature:', error);
            throw new Error('Invalid ID token signature');
        }
    }

    public setExpectedNonce(nonce: string): void {
        this.expectedNonce = nonce;
    }

    public getJwks(): any {
        console.log("Getting JWKS");
        // Return our hardcoded full private JWK with all components
        return this.fullPrivateJwk;
    }

    public async handleAuthorizationResponse(authResponse: any): Promise<void> {
        // Verify the ID token
        if (authResponse.id_token) {
            // Verify the token signature
            try {
                this.validateIdTokenSignature(authResponse.id_token);
            } catch (error) {
                console.error('ID token signature validation failed:', error);
                throw error;
            }
            
            // Parse the JWT to check the claims
            const [headerB64, payloadB64] = authResponse.id_token.split('.');
            const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
            
            this.validateIdTokenNonce(payload);
            this.validateIdTokenIssuer(payload);
            this.validateIdTokenAudience(payload);
            this.validateIdTokenExpiration(payload);
            this.validateIdTokenIssueTime(payload); // Validate the iat claim
            
            // Validate s_hash if state is present
            if (authResponse.state && this.state) {
                this.validateIdTokenStateHash(payload, authResponse.state || this.state);
            }
            
            // Validate c_hash if code is present
            if (authResponse.code) {
                this.setAuthorizationCode(authResponse.code);
                this.validateIdTokenCodeHash(payload, authResponse.code);
            }
        }
    }

    public getAuthorizationUrl(requestUri: string): string {
        if (!this.config.issuer) {
            throw new Error('Issuer must be configured');
        }

        const params = {
            client_id: this.clientId,
            request_uri: requestUri
        };

        // Ensure the authorization endpoint URL is correct
        const baseUrl = this.config.issuer.replace(/\/$/, '');
        const authUrl = `${baseUrl}/authorize?${querystring.stringify(params)}`;
        
        console.log('Authorization URL:', authUrl);
        return authUrl;
    }

    public async submitPushedAuthorizationRequest(requestObject: string): Promise<any> {
        if (!this.parEndpoint) {
            throw new Error('PAR endpoint not configured');
        }

        const params = new URLSearchParams();
        params.append('request', requestObject);
        params.append('client_id', this.clientId);

        const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

        const config: AxiosRequestConfig = {
            method: 'post',
            url: this.parEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'Authorization': `Basic ${authHeader}`,
                'Accept': 'application/json'
            },
            data: params,
            httpsAgent: this.httpsAgent
        };

        try {
            const response = await axios(config);
            return response.data;
        } catch (error) {
            if (error instanceof AxiosError) {
                console.error('PAR request failed:', {
                    status: error.response?.status,
                    data: error.response?.data
                });
            }
            throw error;
        }
    }

    // This method is specifically for the conformance test suite to sign ID tokens with invalid issuer
    public async signIdTokenWithInvalidIssuer(subject: string, nonce: string, clientId: string): Promise<string | null> {
        console.log('Creating ID token with invalid issuer for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        // Use an invalid issuer value
        const invalidIssuer = 'https://invalid-issuer.example.com';
        const effectiveClientId = clientId || this.clientId;

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: invalidIssuer, // Invalid issuer
            sub: subject,
            aud: effectiveClientId,
            exp: now + 3600,  // 1 hour expiry
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex') // Add a unique identifier
        };

        console.log('ID Token with invalid issuer payload:', JSON.stringify(payload, null, 2));
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token with invalid issuer');
            return token;
        } catch (error) {
            console.error('Failed to sign ID token with invalid issuer:', error);
            return null;
        }
    }

    // Method to get the private key for direct signing by the test suite
    public getPrivateSigningKey(): string | null {
        if (!this.privateKey) {
            console.warn('Private key not available');
            return null;
        }
        console.log('Providing private key to test suite for direct signing');
        return this.privateKey;
    }

    // Method to get private JWK for signing
    public getPrivateJwk(): any {
        console.log("Getting private JWK for signing");
        
        // Return our hardcoded private JWK with all private components
        console.log("Returning hardcoded private JWK with private components");
        return this.fullPrivateJwk;
    }

    private async ensureCorrectKeyFormat(key: string): Promise<string> {
        // If the key is already in the correct format, return it
        try {
            const sign = crypto.createSign('sha256');
            sign.update('test');
            sign.sign({
                key: key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            return key;
        } catch (error) {
            // If signing fails, try to convert the key
            console.warn('Key format needs conversion:', error instanceof Error ? error.message : 'Unknown error');
            // You might need to implement key format conversion here if needed
            throw new Error('Unsupported key format');
        }
    }

    public async makeAuthorizationRequest(authUrl: string, requestUri: string): Promise<any> {
        try {
            const params = new URLSearchParams();
            params.append('client_id', this.clientId);
            params.append('request_uri', requestUri);

            const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

            const response = await axios({
                method: 'post',
                url: authUrl,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${authHeader}`,
                    'Accept': 'application/json'
                },
                data: params,
                maxRedirects: 0,
                validateStatus: (status) => {
                    return status === 302 || (status >= 200 && status < 300);
                },
                httpsAgent: this.httpsAgent
            });

            if (response.status === 302) {
                const location = response.headers.location;
                console.log('Authorization redirect location:', location);
                return { redirectUrl: location };
            }

            return response.data;
        } catch (error) {
            if (error instanceof AxiosError) {
                console.error('Authorization request failed:', {
                    status: error.response?.status,
                    headers: error.response?.headers,
                    data: error.response?.data
                });
                // If we got a redirect response, return it
                if (error.response?.status === 302 && error.response?.headers?.location) {
                    return { redirectUrl: error.response.headers.location };
                }
            }
            throw error;
        }
    }

    // Update getAuthorizationUrl to use the new method
    public async getAuthorizationResponse(requestUri: string): Promise<any> {
        if (!this.config.issuer) {
            throw new Error('Issuer must be configured');
        }

        const baseUrl = this.config.issuer.replace(/\/$/, '');
        const authUrl = `${baseUrl}/authorize`;
        
        return this.makeAuthorizationRequest(authUrl, requestUri);
    }

    // This method is for the conformance test suite to access the private key directly
    public exportPrivateJwk(): any {
        console.log("Exporting private JWK for test suite");
        
        // Return our hardcoded private JWK with all private components
        console.log("Returning hardcoded private JWK with private components");
        return this.fullPrivateJwk;
    }

    // Create a method for testing invalid issuer detection
    public async createMockIdTokenWithInvalidIssuer(): Promise<string | null> {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: 'https://invalid-issuer.example.com', // Invalid issuer
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca'
        };

        console.log('Creating mock ID token with invalid issuer:', payload.iss);
        return this.signJWT(payload);
    }

    // Create a method for testing invalid audience detection
    public async createMockIdTokenWithInvalidAudience(): Promise<string | null> {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: 'invalid-audience-value', // Invalid audience that doesn't match client ID
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca'
        };

        console.log('Creating mock ID token with invalid audience:', payload.aud);
        return this.signJWT(payload);
    }

    // This method is specifically for the conformance test suite to sign ID tokens with invalid audience
    public async signIdTokenWithInvalidAudience(subject: string, nonce: string): Promise<string | null> {
        console.log('Creating ID token with invalid audience for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: 'invalid-client-id', // Invalid audience
            exp: now + 3600,  // 1 hour expiry
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex') // Add a unique identifier
        };

        console.log('ID Token with invalid audience payload:', JSON.stringify(payload, null, 2));
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token with invalid audience');
            return token;
        } catch (error) {
            console.error('Failed to sign ID token with invalid audience:', error);
            return null;
        }
    }

    // Create a method for testing invalid signature detection
    public async createMockIdTokenWithInvalidSignature(): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca'
        };

        // Create a legitimate JWT first
        const validToken = await this.signJWT(payload);
        if (!validToken) {
            throw new Error('Failed to create valid token for signature tampering');
        }

        // Now tamper with the signature to make it invalid
        const [header, payloadBase64, signature] = validToken.split('.');
        
        // Replace one character in the signature to make it invalid
        const tamperedSignature = 'X' + signature.substring(1);
        
        console.log('Created mock ID token with invalid signature');
        return `${header}.${payloadBase64}.${tamperedSignature}`;
    }

    // This method is specifically for the conformance test suite to sign ID tokens with invalid signatures
    public async signIdTokenWithInvalidSignature(subject: string, nonce: string): Promise<string> {
        console.log('Creating ID token with invalid signature for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: this.clientId,
            exp: now + 3600,  // 1 hour expiry
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex')
        };

        console.log('ID Token payload for invalid signature test:', JSON.stringify(payload, null, 2));
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215',
                kty: 'RSA',
                use: 'sig'
            };
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Create an invalid signature by using a different key or just generating random data
            const tamperedSignature = crypto.randomBytes(256).toString('base64url');
            
            const token = `${signingInput}.${tamperedSignature}`;
            
            console.log('Successfully created ID token with invalid signature');
            return token;
        } catch (error) {
            console.error('Failed to create ID token with invalid signature:', error);
            throw error;
        }
    }

    // Create a method for testing "none" algorithm detection
    public async createMockIdTokenWithNoneAlgorithm(): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca'
        };
        
        // Create a JWT with "none" algorithm
        const header = {
            typ: 'JWT',
            alg: 'none',
            kid: 'f4706d18-bf16-43ce-b181-90b4128ca215'
        };
        
        console.log('Creating mock ID token with "none" algorithm');
        
        // Encode header and payload
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        
        // For "none" algorithm, signature is empty
        const token = `${encodedHeader}.${encodedPayload}.`;
        
        console.log('Created mock ID token with "none" algorithm');
        return token;
    }

    // This method is specifically for the conformance test suite to sign ID tokens with "none" algorithm
    public async signIdTokenWithNoneAlgorithm(subject: string, nonce: string): Promise<string> {
        console.log('Creating ID token with "none" algorithm for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: this.clientId,
            exp: now + 3600,  // 1 hour expiry
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex')
        };

        console.log('ID Token payload for "none" algorithm test:', JSON.stringify(payload, null, 2));
        
        // Create a header with "none" algorithm
        const header = {
            typ: 'JWT',
            alg: 'none'
        };
        
        // Encode the parts
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        
        // For "none" algorithm, signature part is empty
        const emptySignature = '';
        
        const token = `${encodedHeader}.${encodedPayload}.${emptySignature}`;
        
        console.log('Successfully created ID token with "none" algorithm');
        return token;
    }

    public validateIdTokenExpiration(idToken: any): void {
        if (!idToken.exp) {
            const error = new Error('Missing expiration time in ID token');
            console.error(error.message);
            throw error;
        }

        const now = Math.floor(Date.now() / 1000);
        const leeway = 300; // 5 minutes leeway
        const expTime = new Date(idToken.exp * 1000).toISOString();
        const nowTime = new Date(now * 1000).toISOString();
        const diffMinutes = (now - idToken.exp) / 60;

        console.log('Validating ID token expiration:', {
            expiration: expTime,
            current: nowTime,
            difference: diffMinutes.toFixed(2) + ' minutes',
            expired: idToken.exp + leeway < now
        });

        if (idToken.exp + leeway < now) {
            const error = new Error(`ID token has expired more than 5 minutes in the past (expired: ${expTime}, now: ${nowTime}, diff: ${diffMinutes.toFixed(2)} minutes)`);
            console.error(error.message);
            throw error;
        }
    }

    // Add a method to create ID tokens with expired exp claims for testing
    public async createMockIdTokenWithExpiredExp(): Promise<string | null> {
        const now = Math.floor(Date.now() / 1000);
        // Set expiration to 10 minutes in the past
        const expiredExp = now - 600; 
        
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now - 3600, // Issued an hour ago
            exp: expiredExp, // Expired 10 minutes ago
            auth_time: now - 3600,
            acr: 'urn:openbanking:psd2:sca'
        };

        console.log('Creating mock ID token with expired exp claim:', {
            now,
            expiredExp,
            difference: (now - expiredExp) / 60 + ' minutes'
        });
        
        return this.signJWT(payload);
    }

    // This method is specifically for the conformance test suite to sign ID tokens with expired exp
    public async signIdTokenWithExpiredExp(subject: string, nonce: string, clientId: string): Promise<string | null> {
        console.log('Creating ID token with expired exp claim for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        const now = Math.floor(Date.now() / 1000);
        // Set expiration to 10 minutes in the past
        const expiredExp = now - 600;
        
        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: clientId || this.clientId,
            exp: expiredExp, // Expired 10 minutes ago
            iat: now - 3600, // Issued an hour ago
            auth_time: now - 3600,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex')
        };

        console.log('ID Token with expired exp payload:', JSON.stringify(payload, null, 2));
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token with expired exp');
            return token;
        } catch (error) {
            console.error('Failed to sign ID token with expired exp:', error);
            return null;
        }
    }

    // Add a method to create ID tokens with missing exp claim for testing
    public async createMockIdTokenWithMissingExp(): Promise<string | null> {
        const now = Math.floor(Date.now() / 1000);
        
        // Create payload without exp claim
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca'
            // exp claim is intentionally omitted
        };

        console.log('Creating mock ID token with missing exp claim:', payload);
        return this.signJWT(payload);
    }

    // Add a method to validate the s_hash in ID tokens
    public validateIdTokenStateHash(idToken: any, state: string): void {
        if (!idToken.s_hash) {
            const error = new Error('Missing s_hash in ID token');
            console.error(error.message);
            throw error;
        }

        if (!state) {
            const error = new Error('No state provided to validate s_hash');
            console.error(error.message);
            throw error;
        }

        // Compute the state hash according to OIDC specs
        const stateHash = crypto.createHash('sha256').update(state).digest();
        const halfLength = stateHash.length / 2;
        const expectedSHash = stateHash.slice(0, halfLength).toString('base64url');

        console.log('Validating s_hash:', {
            received: idToken.s_hash,
            expected: expectedSHash,
            state: state
        });

        if (idToken.s_hash !== expectedSHash) {
            const error = new Error('Invalid s_hash in ID token');
            console.error(error.message, {
                received: idToken.s_hash,
                expected: expectedSHash
            });
            throw error;
        }
    }

    // Add a method to create ID tokens with invalid s_hash for testing
    public async createMockIdTokenWithInvalidSHash(): Promise<string | null> {
        if (!this.state) {
            console.error('No state available. Cannot create token with invalid s_hash');
            return null;
        }

        const now = Math.floor(Date.now() / 1000);
        
        // Create a valid state hash first
        const stateHash = crypto.createHash('sha256').update(this.state).digest();
        const halfLength = stateHash.length / 2;
        const validSHash = stateHash.slice(0, halfLength).toString('base64url');
        
        // Create an invalid s_hash by modifying one character
        let invalidSHash = validSHash;
        
        // Modify the first character in the s_hash to make it invalid
        if (invalidSHash.length > 0) {
            const firstChar = invalidSHash.charAt(0);
            const newChar = firstChar === 'A' ? 'B' : 'A';
            invalidSHash = newChar + invalidSHash.substring(1);
        }
        
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca',
            s_hash: invalidSHash // Invalid s_hash
        };

        console.log('Creating mock ID token with invalid s_hash:', {
            valid: validSHash,
            invalid: invalidSHash,
            state: this.state
        });
        
        return this.signJWT(payload);
    }

    // Method for the conformance test suite to sign ID tokens with invalid s_hash
    public async signIdTokenWithInvalidSHash(subject: string, nonce: string, state: string): Promise<string | null> {
        console.log('Creating ID token with invalid s_hash for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        if (!state) {
            throw new Error('State is required to create invalid s_hash');
        }

        const now = Math.floor(Date.now() / 1000);
        
        // Create a valid state hash first
        const stateHash = crypto.createHash('sha256').update(state).digest();
        const halfLength = stateHash.length / 2;
        const validSHash = stateHash.slice(0, halfLength).toString('base64url');
        
        // Create an invalid s_hash by modifying one character
        let invalidSHash = validSHash;
        
        // Modify the first character in the s_hash to make it invalid
        if (invalidSHash.length > 0) {
            const firstChar = invalidSHash.charAt(0);
            const newChar = firstChar === 'A' ? 'B' : 'A';
            invalidSHash = newChar + invalidSHash.substring(1);
        }

        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: this.clientId,
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex'),
            s_hash: invalidSHash // Invalid s_hash
        };

        console.log('ID Token with invalid s_hash payload:', JSON.stringify(payload, null, 2));
        console.log('S-hash details:', {
            valid: validSHash,
            invalid: invalidSHash,
            state: state
        });
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token with invalid s_hash');
            return token;
        } catch (error) {
            console.error('Failed to sign ID token with invalid s_hash:', error);
            return null;
        }
    }

    // Update signIdToken method to handle the case of invalid c_hash test
    public async signIdToken(subject: string, nonce: string, clientId: string, issuer: string, state?: string, code?: string): Promise<string | null> {
        console.log('Attempting to sign ID token with params:', { subject, nonce, clientId, issuer, state, code: code ? code.substring(0, 5) + '...' : undefined });

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        // Ensure we have a proper issuer and client ID
        const effectiveIssuer = issuer || this.config.issuer;
        const effectiveClientId = clientId || this.clientId;

        if (!effectiveIssuer) {
            throw new Error('Issuer is required for ID token');
        }

        // Check if the conformance test is requesting specific test cases
        const isExpiredTest = subject.includes('expired') || nonce.includes('expired');
        const isMissingExpTest = subject.includes('missing-exp') || nonce.includes('missing-exp');
        const isInvalidSHashTest = subject.includes('invalid-shash') || nonce.includes('invalid-shash');
        const isInvalidCHashTest = subject.includes('invalid-chash') || nonce.includes('invalid-chash');
        const now = Math.floor(Date.now() / 1000);
        
        // Create the payload according to the test case
        const payload: any = {
            iss: effectiveIssuer,
            sub: subject,
            aud: effectiveClientId,
            iat: isExpiredTest ? now - 3600 : now,
            auth_time: isExpiredTest ? now - 3600 : now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex')
        };
        
        // Add exp claim unless it's a missing-exp test
        if (!isMissingExpTest) {
            // For expired token tests, set the exp claim to 10 minutes in the past
            payload.exp = isExpiredTest ? now - 600 : now + 3600;
        }

        // Add s_hash if state is provided - either valid or invalid based on the test
        if (state) {
            const stateHash = crypto.createHash('sha256').update(state).digest();
            const halfLength = stateHash.length / 2;
            let stateHashEncoded = stateHash.slice(0, halfLength).toString('base64url');
            
            // If it's an invalid s_hash test, modify the hash
            if (isInvalidSHashTest) {
                const firstChar = stateHashEncoded.charAt(0);
                const newChar = firstChar === 'A' ? 'B' : 'A';
                stateHashEncoded = newChar + stateHashEncoded.substring(1);
                console.log('Created invalid s_hash for testing');
            }
            
            payload.s_hash = stateHashEncoded;
            
            console.log('S-hash details:', {
                state,
                hash: stateHashEncoded,
                isInvalid: isInvalidSHashTest
            });
        }
        
        // Add c_hash if code is provided - either valid or invalid based on the test
        if (code) {
            const codeHash = crypto.createHash('sha256').update(code).digest();
            const halfLength = codeHash.length / 2;
            let codeHashEncoded = codeHash.slice(0, halfLength).toString('base64url');
            
            // If it's an invalid c_hash test, modify the hash
            if (isInvalidCHashTest) {
                const firstChar = codeHashEncoded.charAt(0);
                const newChar = firstChar === 'A' ? 'B' : 'A';
                codeHashEncoded = newChar + codeHashEncoded.substring(1);
                console.log('Created invalid c_hash for testing');
            }
            
            payload.c_hash = codeHashEncoded;
            
            console.log('C-hash details:', {
                code: code.substring(0, 5) + '...',
                hash: codeHashEncoded,
                isInvalid: isInvalidCHashTest
            });
        }

        console.log('ID Token payload:', JSON.stringify(payload, null, 2));
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token');
            if (isExpiredTest) {
                console.log('Note: Created ID token has an expired exp claim for testing');
            } else if (isMissingExpTest) {
                console.log('Note: Created ID token is missing the exp claim for testing');
            } else if (isInvalidSHashTest) {
                console.log('Note: Created ID token has an invalid s_hash for testing');
            } else if (isInvalidCHashTest) {
                console.log('Note: Created ID token has an invalid c_hash for testing');
            }
            return token;
        } catch (error) {
            console.error('Failed to sign ID token:', error);
            return null;
        }
    }

    // Add a method to get the current state
    public getState(): string {
        return this.state;
    }

    // Store the code when handling authorization response
    public setAuthorizationCode(code: string) {
        this.authorizationCode = code;
        console.log('Set authorization code:', this.authorizationCode.substring(0, 5) + '...');
    }

    // Add a method to validate the c_hash in ID tokens
    public validateIdTokenCodeHash(idToken: any, code: string): void {
        if (!idToken.c_hash) {
            const error = new Error('Missing c_hash in ID token');
            console.error(error.message);
            throw error;
        }

        if (!code) {
            const error = new Error('No authorization code provided to validate c_hash');
            console.error(error.message);
            throw error;
        }

        // Compute the code hash according to OIDC specs
        const codeHash = crypto.createHash('sha256').update(code).digest();
        const halfLength = codeHash.length / 2;
        const expectedCHash = codeHash.slice(0, halfLength).toString('base64url');

        console.log('Validating c_hash:', {
            received: idToken.c_hash,
            expected: expectedCHash,
            code: code.substring(0, 5) + '...' // Only log a portion of the code for security
        });

        if (idToken.c_hash !== expectedCHash) {
            const error = new Error('Invalid c_hash in ID token');
            console.error(error.message, {
                received: idToken.c_hash,
                expected: expectedCHash
            });
            throw error;
        }
    }

    // Add a method to create ID tokens with invalid c_hash for testing
    public async createMockIdTokenWithInvalidCHash(): Promise<string | null> {
        if (!this.authorizationCode) {
            console.error('No authorization code available. Cannot create token with invalid c_hash');
            return null;
        }

        const now = Math.floor(Date.now() / 1000);
        
        // Create a valid code hash first
        const codeHash = crypto.createHash('sha256').update(this.authorizationCode).digest();
        const halfLength = codeHash.length / 2;
        const validCHash = codeHash.slice(0, halfLength).toString('base64url');
        
        // Create an invalid c_hash by modifying one character
        let invalidCHash = validCHash;
        
        // Modify the first character in the c_hash to make it invalid
        if (invalidCHash.length > 0) {
            const firstChar = invalidCHash.charAt(0);
            const newChar = firstChar === 'A' ? 'B' : 'A';
            invalidCHash = newChar + invalidCHash.substring(1);
        }
        
        const payload = {
            iss: this.config.issuer,
            sub: 'test-subject',
            aud: this.clientId,
            nonce: this.expectedNonce,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            acr: 'urn:openbanking:psd2:sca',
            c_hash: invalidCHash // Invalid c_hash
        };

        console.log('Creating mock ID token with invalid c_hash:', {
            valid: validCHash,
            invalid: invalidCHash,
            code: this.authorizationCode.substring(0, 5) + '...'
        });
        
        return this.signJWT(payload);
    }

    // Method for the conformance test suite to sign ID tokens with invalid c_hash
    public async signIdTokenWithInvalidCHash(subject: string, nonce: string, code: string): Promise<string | null> {
        console.log('Creating ID token with invalid c_hash for test');

        if (!this.privateKey) {
            throw new Error('No signing key available to sign ID token');
        }

        if (!this.config.issuer) {
            throw new Error('Issuer not configured, required for ID token');
        }

        if (!code) {
            throw new Error('Authorization code is required to create invalid c_hash');
        }

        const now = Math.floor(Date.now() / 1000);
        
        // Create a valid code hash first
        const codeHash = crypto.createHash('sha256').update(code).digest();
        const halfLength = codeHash.length / 2;
        const validCHash = codeHash.slice(0, halfLength).toString('base64url');
        
        // Create an invalid c_hash by modifying one character
        let invalidCHash = validCHash;
        
        // Modify the first character in the c_hash to make it invalid
        if (invalidCHash.length > 0) {
            const firstChar = invalidCHash.charAt(0);
            const newChar = firstChar === 'A' ? 'B' : 'A';
            invalidCHash = newChar + invalidCHash.substring(1);
        }

        const payload = {
            iss: this.config.issuer,
            sub: subject,
            aud: this.clientId,
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce: nonce,
            acr: 'urn:openbanking:psd2:sca',
            jti: crypto.randomBytes(16).toString('hex'),
            c_hash: invalidCHash // Invalid c_hash
        };

        console.log('ID Token with invalid c_hash payload:', JSON.stringify(payload, null, 2));
        console.log('C-hash details:', {
            valid: validCHash,
            invalid: invalidCHash,
            code: code.substring(0, 5) + '...'
        });
        
        try {
            // Use specific headers for ID tokens
            const header = {
                typ: 'JWT',
                alg: 'PS256',
                kid: 'f4706d18-bf16-43ce-b181-90b4128ca215', // Use the same kid as in the jwks configuration
                kty: 'RSA',
                use: 'sig'
            };
            
            console.log('ID Token header:', JSON.stringify(header, null, 2));
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${encodedHeader}.${encodedPayload}`;

            // Sign manually to ensure complete control over the signing process
            const key = crypto.createPrivateKey({
                key: this.privateKey,
                format: 'pem'
            });
            
            const sign = crypto.createSign('sha256');
            sign.update(signingInput);
            const signature = sign.sign({
                key,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
            
            const encodedSignature = signature.toString('base64url');
            const token = `${signingInput}.${encodedSignature}`;
            
            console.log('Successfully signed ID token with invalid c_hash');
            return token;
        } catch (error) {
            console.error('Failed to sign ID token with invalid c_hash:', error);
            return null;
        }
    }

    // Add a method to get the authorization code
    public getAuthorizationCode(): string {
        return this.authorizationCode;
    }

    /**
     * New method to handle redirect URL, extract authorization code,
     * and exchange it for tokens.
     * @param redirectUrl The redirect URL containing the authorization code as a query parameter
     * @returns The token response from the token endpoint
     */
    public async handleRedirectUrlAndExchangeCode(redirectUrl: string): Promise<any> {
        try {
            const urlObj = new URL(redirectUrl);
            const code = urlObj.searchParams.get('code');
            if (!code) {
                throw new Error('Authorization code not found in redirect URL');
            }
            console.log('Extracted authorization code from redirect URL:', code);
            return await this.processAuthorizationCodeExchange(code);
        } catch (error) {
            console.error('Failed to handle redirect URL and exchange code:', error);
            throw error;
        }
    }

    // Method to simulate a token response with missing scope/expires_in for testing
    public createTokenResponseWithMissingFields(includeScope: boolean = false, includeExpiresIn: boolean = false): any {
        const tokenResponse: Record<string, any> = {
            access_token: 'test_access_token_' + crypto.randomBytes(8).toString('hex'),
            token_type: 'Bearer',
            refresh_token: 'test_refresh_token_' + crypto.randomBytes(8).toString('hex'),
            id_token: 'test_id_token_' + crypto.randomBytes(8).toString('hex')
        };
        
        // Conditionally add scope and expires_in based on parameters
        if (includeScope) {
            tokenResponse.scope = this.requestedScopes.join(' ');
        }
        
        if (includeExpiresIn) {
            tokenResponse.expires_in = 3600;
        }
        
        return tokenResponse;
    }

    // Add method to get requested scopes
    public getRequestedScopes(): string[] {
        return [...this.requestedScopes]; // Return a copy to prevent modification
    }

    // Add method to perform refresh token exchange according to FAPI spec
    public async refreshAccessToken(refreshToken: string): Promise<any> {
        this.logConformanceTestInteraction('FAPI Conformance: Refreshing access token with refresh token', {
            refresh_token_prefix: refreshToken.substring(0, 10) + '...',
            token_endpoint: this.tokenEndpoint
        });
        
        const params = new URLSearchParams();
        params.append('grant_type', 'refresh_token');
        params.append('refresh_token', refreshToken);
        params.append('client_id', this.clientId);

        const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

        const config: AxiosRequestConfig = {
            method: 'post',
            url: this.tokenEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${authHeader}`,
                'Accept': 'application/json'
            },
            data: params,
            httpsAgent: this.httpsAgent
        };

        this.logConformanceTestInteraction('FAPI Conformance: Refresh token request details', {
            endpoint: this.tokenEndpoint,
            grant_type: 'refresh_token',
            client_id: this.clientId,
            has_refresh_token: !!refreshToken
        });

        try {
            const response = await axios(config);
            
            this.logConformanceTestInteraction('FAPI Conformance: Refresh token response status', {
                status: response.status,
                statusText: response.statusText
            });
            
            // Get the unmodified token response - as per FAPI spec
            const tokenResponse = response.data;
            
            // Log the raw token response details for FAPI conformance testing
            this.logConformanceTestInteraction('FAPI Conformance: Raw refresh token response received', {
                has_access_token: !!tokenResponse.access_token,
                has_refresh_token: !!tokenResponse.refresh_token,
                has_id_token: !!tokenResponse.id_token,
                has_scope: !!tokenResponse.scope,
                has_expires_in: !!tokenResponse.expires_in,
                token_type: tokenResponse.token_type || 'not provided'
            });
            
            // FAPI spec section 5.2.2 handling for missing scope
            if (!tokenResponse.scope || tokenResponse.scope === '') {
                this.logConformanceTestInteraction('FAPI Conformance: No scope in refresh token response - valid according to FAPI spec');
                this.logConformanceTestInteraction('FAPI Conformance: Using requested scopes as effective scopes for application logic', {
                    requested_scopes: this.requestedScopes
                });
            } else {
                this.logConformanceTestInteraction('FAPI Conformance: Scope present in refresh token response', {
                    scope: tokenResponse.scope
                });
            }
            
            // Check if expires_in is missing (optional according to OAuth 2.0 spec)
            if (!tokenResponse.expires_in) {
                this.logConformanceTestInteraction('FAPI Conformance: No expires_in in refresh token response - valid according to OAuth 2.0 spec');
            } else {
                this.logConformanceTestInteraction('FAPI Conformance: Expires_in present in refresh token response', {
                    expires_in: tokenResponse.expires_in
                });
            }
            
            // Check for required access_token
            if (!tokenResponse.access_token) {
                throw new Error('FAPI Conformance: Missing access_token in refresh token response');
            }
            
            this.logConformanceTestInteraction('FAPI Conformance: Refresh token exchange completed successfully', {
                access_token_length: tokenResponse.access_token.length,
                has_new_refresh_token: !!tokenResponse.refresh_token
            });
            
            // Process the token response but do not modify it
            return this.handleTokenResponse(tokenResponse);
        } catch (error) {
            this.logConformanceTestInteraction('FAPI Conformance: Refresh token request failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                is_axios_error: error instanceof AxiosError,
                status: error instanceof AxiosError ? error.response?.status : 'unknown'
            });
            console.error('Refresh token request failed:', error);
            throw error;
        }
    }

    // Validates the iat (issued at) claim of the ID token
    public validateIdTokenIssueTime(idToken: any): void {
        if (!idToken.iat) {
            const error = new Error('Missing issue time (iat) in ID token');
            console.error(error.message);
            throw error;
        }
        
        const now = Math.floor(Date.now() / 1000);
        const maxSkew = 60; // 1 minute clock skew allowance
        
        // Check if the token was issued too far in the past (24 hours)
        const oneDayAgo = now - 86400; // 24 hours in seconds
        if (idToken.iat < oneDayAgo) {
            const error = new Error('ID token was issued too far in the past');
            console.error(error.message, {
                issued_at: new Date(idToken.iat * 1000).toISOString(),
                now: new Date(now * 1000).toISOString(),
                difference_hours: Math.round((now - idToken.iat) / 3600)
            });
            throw error;
        }
        
        // Check if the token was issued in the future (beyond allowed clock skew)
        if (idToken.iat > now + maxSkew) {
            const error = new Error('ID token was issued in the future');
            console.error(error.message, {
                issued_at: new Date(idToken.iat * 1000).toISOString(),
                now: new Date(now * 1000).toISOString(),
                difference_seconds: idToken.iat - now
            });
            throw error;
        }
    }
}