# FAPI Client Project

This project is a TypeScript implementation of a Financial-grade API (FAPI) client, supporting OAuth2/OpenID Connect flows with advanced features such as pushed authorization requests (PAR), mutual TLS, and refresh token handling.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Build the project:

```bash
npm run build
```

## Running Tests

The main test entry point is `src/index.ts`, which includes various conformance tests.

### Running the Refresh Token Flow Test

This test performs the full authorization code flow, exchanges the authorization code for tokens, and tests refresh token handling.

Run the test with:

```bash
node dist/index.js refresh-token <discoveryUrl> <resourceEndpoint>
```

Replace `<discoveryUrl>` and `<resourceEndpoint>` with the appropriate URLs for your environment.

### Testing with a Redirect URL Directly

If you have a redirect URL containing an authorization code (e.g., obtained manually or from a browser), you can test the token exchange directly:

1. Open `src/index.ts`.

2. Locate the `testRefreshTokenFlow` function.

3. Uncomment the example lines near the top of the function that look like this:

```typescript
/*
const redirectUrl = 'https://localhost.emobix.co.uk:8443/test/a/ais-corporate/callback?code=YOUR_AUTH_CODE&state=xyz';
console.log('Using provided redirect URL:', redirectUrl);
const tokenResponse = await client.handleRedirectUrlAndExchangeCode(redirectUrl);
console.log('Token response:', tokenResponse);
return; // Exit early since we are testing direct redirect URL handling
*/
```

4. Replace the `redirectUrl` string with your actual redirect URL.

5. Build the project again if needed.

6. Run the test script without parameters:

```bash
node dist/index.js refresh-token
```

The test will use the provided redirect URL to exchange the authorization code for tokens and output the result.

## Notes

- The project requires Node.js and npm.

- Certificates and keys for mutual TLS should be placed in the `src/certs` directory as configured in `src/index.ts`.

- The client configuration is set in `src/index.ts` in the `main` function.

## Scripts

- `npm run build` - Compile TypeScript to JavaScript.

- `npm start` - Run the main test script (after build).

## License

MIT License
