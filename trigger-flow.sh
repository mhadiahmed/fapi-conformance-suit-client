#!/bin/bash
# Script to trigger the FAPI authorization flow for conformance testing

echo "Triggering FAPI authorization flow..."
echo ""

response=$(curl -X POST http://localhost:8080/trigger-flow \
  -H "Content-Type: application/json" \
  -s)

# Pretty print the response
echo "$response" | jq .

# Extract and display the authorization URL
auth_url=$(echo "$response" | jq -r '.authorizationUrl')

if [ "$auth_url" != "null" ] && [ -n "$auth_url" ]; then
    echo ""
    echo "=========================================="
    echo "Authorization URL:"
    echo "$auth_url"
    echo "=========================================="
    echo ""
    echo "Open this URL in your browser to complete the authorization."
else
    echo "Failed to get authorization URL. Check the error above."
    exit 1
fi

