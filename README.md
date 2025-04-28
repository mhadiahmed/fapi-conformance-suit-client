# FAPI Client Python Implementation

This project implements a FAPI (Financial-grade API) client in Python, suitable for use with the FAPI Conformance Test Suite.

## Overview

The Financial-grade API (FAPI) is a technical specification for financial services APIs that require high security. This implementation provides a client that can interact with FAPI-compliant servers and pass the FAPI conformance tests.

## Features

- Full implementation of FAPI client functionality
- Support for mTLS (mutual TLS)
- JWT signing with PKCS#1 and PKCS#8 private keys
- JWKS (JSON Web Key Set) handling with private key components
- Pushed Authorization Requests (PAR)
- Request Object signing
- Account consent requests
- Authorization code flow
- Client credentials flow

## Requirements

- Python 3.8+
- Required packages listed in `requirements.txt`

## Installation

1. Clone this repository
2. Install the required packages:

```bash
pip install -r requirements.txt
```

3. Make sure you have the necessary certificates in the `certs/` directory:
   - `client.crt` - Client certificate for mTLS
   - `client.key` - Client key for mTLS
   - `signin-key-Seen Tarbi for Fintech-seen-tarbee-corporate.pem` - Signing key for JWTs

## Usage

### Basic Setup

```python
from fapi_client import FAPIClient

config = {
    'client_id': 'your-client-id',
    'client_secret': 'your-client-secret',
    'token_endpoint': 'https://example.com/token',
    'par_endpoint': 'https://example.com/par',
    'issuer': 'https://example.com',
    'redirect_uri': 'https://your-app.com/callback',
    'cert_path': 'path/to/client.crt',
    'key_path': 'path/to/client.key',
    'signing_key_path': 'path/to/signing-key.pem'
}

client = FAPIClient(config)
client.set_requested_scopes(['openid', 'accounts'])
```

### Complete Flow

To execute a complete authorization flow:

```bash
python main.py
```

This will:
1. Create an account consent request
2. Create and submit a pushed authorization request
3. Generate an authorization URL
4. Make the authorization request
5. Handle the response or redirect

## Components

- `fapi_client.py` - The main FAPI client implementation
- `main.py` - Example script demonstrating usage of the FAPI client
- `requirements.txt` - Required Python packages
- `certs/` - Directory for certificates and keys

## Advantages over Node.js Implementation

The Python implementation offers several advantages:
1. Better cryptography support with the `cryptography` and `jose` libraries
2. Simpler handling of JWKs and private key components
3. More comprehensive error handling
4. Better handling of different key formats (PKCS#1 and PKCS#8)
5. Improved logging and debugging capabilities

## License

ISC License 