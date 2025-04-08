# Flask Keycloak OIDC Integration Example

Note: This project is vibecoded

This project demonstrates how to implement OpenID Connect (OIDC) authentication using Flask and Keycloak. It serves as a reference implementation for authentication and authorization using OIDC protocol.

## Overview

This application showcases:
- OpenID Connect authentication flow with Keycloak
- Token validation and verification
- Protected routes using decorators
- User information retrieval
- Session management

## Prerequisites

- Python 3.x
- Flask
- Keycloak server instance
- Required Python packages:
  ```bash
  pip install flask requests pyjwt python-jose
  ```

## Configuration

Create a `config.py` file with the following Keycloak configuration:

```python
class Config:
    FLASK_SECRET_KEY = "your-secret-key"
    KEYCLOAK_URL = "http://your-keycloak-server"
    KEYCLOAK_REALM = "your-realm"
    KEYCLOAK_CLIENT_ID = "your-client-id"
    KEYCLOAK_CLIENT_SECRET = "your-client-secret"
    KEYCLOAK_REDIRECT_URI = "http://localhost:3000/callback"
    
    # Derived URLs
    KEYCLOAK_AUTH_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    KEYCLOAK_TOKEN_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    KEYCLOAK_USERINFO_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
    KEYCLOAK_JWKS_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
```

## Features

### 1. Authentication Flow
- Implements OIDC Authorization Code flow
- Secure state and nonce handling
- Token exchange and validation

### 2. Security Features
- JWT validation using RS256 algorithm
- JWKS (JSON Web Key Set) integration
- Token signature verification
- Nonce validation to prevent replay attacks
- Authorized party (azp) verification

### 3. Protected Routes
The application includes a decorator `@require_valid_token` for protecting routes:

```python
@app.route('/protected')
@require_valid_token
def protected():
    return "This is a protected endpoint!"
```

### 4. Available Endpoints

- `/` - Home page with login link
- `/login` - Initiates OIDC authentication flow
- `/callback` - OIDC callback handler
- `/userinfo` - Fetches authenticated user information
- `/logout` - Ends user session
- `/foo` - Example protected endpoint with manual token validation
- `/fiz` - Example protected endpoint using decorator

## Understanding the Flow

1. **Authentication Initiation**
   - User visits `/login`
   - Application generates state and nonce
   - Redirects to Keycloak login page

2. **Token Exchange**
   - Keycloak redirects back with authorization code
   - Application exchanges code for tokens
   - Validates ID token and nonce

3. **Protected Resources**
   - Access token stored in session
   - Token validated for each protected request
   - User information retrieved from Keycloak

## Security Considerations

- Always use HTTPS in production
- Implement proper session management
- Store tokens securely
- Validate all tokens and claims
- Implement proper error handling
- Use secure random values for state and nonce

## Running the Application

1. Set up your Keycloak server and create a client
2. Configure the `config.py` file
3. Run the application:
   ```bash
   python server.py
   ```
4. Visit http://localhost:3000

## Common Issues and Troubleshooting

1. **Token Validation Failures**
   - Verify Keycloak realm and client configuration
   - Check token expiration
   - Ensure correct signing algorithms

2. **Callback Errors**
   - Verify redirect URI configuration
   - Check client secret
   - Validate state parameter

## Contributing

Feel free to submit issues and enhancement requests!

## License

Apache 2.0
