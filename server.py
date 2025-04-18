from flask import Flask, redirect, request, session, url_for, jsonify
import requests
import secrets
import jwt
from jwt import PyJWKClient
from functools import wraps
import urllib.parse
from config import Config

config = Config()

# Flask app setup
app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

keycloak_url = config.KEYCLOAK_URL
redirect_uri = config.KEYCLOAK_REDIRECT_URI 
authorization_url = config.KEYCLOAK_AUTH_URL
token_url = config.KEYCLOAK_TOKEN_URL
userinfo_url = config.KEYCLOAK_USERINFO_URL
jwks_url = config.KEYCLOAK_JWKS_URL
client_id = config.KEYCLOAK_CLIENT_ID
client_secret = config.KEYCLOAK_CLIENT_SECRET
realm = config.KEYCLOAK_REALM

def require_valid_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"[Protected Endpoint] {request.method} {request.path}")
        print(f"[Function Name] {f.__name__}")

        access_token = session.get('access_token')
        if not access_token:
            return "Unauthorized - Please login first", 401
        
        try:
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(access_token)
            
            # Verify the token
            decoded_token = jwt.decode(
                access_token,
                signing_key.key,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=f"{keycloak_url}/realms/{realm}"
            )
            
            # Verify the authorized party (azp)
            if decoded_token.get('azp') != client_id:
                return "Invalid authorized party", 401
                
            # Add decoded token to request context for use in the endpoint
            request.token = decoded_token

            print(f"Decoded token: {decoded_token}")
            
            return f(*args, **kwargs)
            
        except jwt.InvalidTokenError as e:
            return f"Token validation failed: {str(e)}", 401
            
    return decorated_function

@app.route('/')
def index():
    return 'Welcome to the OIDC Demo with Keycloak! <a href="/login">Login</a>'

@app.route('/login')
def login():
    # Redirect to Keycloak authorization endpoint
    state = secrets.token_urlsafe(16) # In production, this should be random and secure
    nonce = secrets.token_urlsafe(16)

    session['nonce'] = nonce
    
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state,
        'nonce': nonce
    }
    auth_request = f"{authorization_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_request)

@app.route('/callback')
def callback():
    # Get the authorization code from the callback URL
    code = request.args.get('code')
    if code is None:
        return "No authorization code found", 400

    # Exchange the authorization code for an access token and ID token
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri
    }
    token_response = requests.post(token_url, data=token_data)
    
    if token_response.status_code != 200:
        return f"Failed to exchange code: {token_response.text}", 400

    tokens = token_response.json()
    access_token = tokens.get('access_token')
    id_token = tokens.get('id_token')

    print(f"Access token: {access_token}")
    print(f"ID token: {id_token}")

    # Verify the ID token and its nonce
    try:
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        
        decoded_id_token = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer=f"{keycloak_url}/realms/{realm}"
        )
        
        # Verify nonce matches
        expected_nonce = session.get('nonce')
        if decoded_id_token.get('nonce') != expected_nonce:
            return "Invalid nonce", 401
            
        # Clear the nonce from session after verification
        session.pop('nonce', None)
        
    except jwt.InvalidTokenError as e:
        return f"ID token validation failed: {str(e)}", 401

    # Store tokens in session (this is just for demo purposes)
    session['access_token'] = access_token
    session['id_token'] = id_token

    # Fetch user information from the UserInfo endpoint
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(userinfo_url, headers=headers)
    
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        return f"User Info: {userinfo}", 200
    else:
        return f"Failed to fetch user info: {userinfo_response.text}", 400

@app.route('/userinfo')
def userinfo():
    # Fetch user info using the access token
    access_token = session.get('access_token')
    if not access_token:
        return "Access token missing. Please log in.", 401
    
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(userinfo_url, headers=headers)
    
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        return jsonify(userinfo)
    else:
        return f"Failed to fetch user info: {userinfo_response.text}", 400

@app.route('/logout')
def logout():
    # Logout the user (revoke tokens, end session, etc.)
    session.clear()
    return redirect(url_for('index'))

@app.route('/foo')
def foo():
    access_token = session.get('access_token')
    print(f"Access token: {access_token}")
    if not access_token:
        return "Unauthorized - Please login first", 401
    
    try:
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        print(f"Signing key: {signing_key}")

        decoded_token = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=['RS256'],
            options={"verify_aud": False},
            issuer=f'{keycloak_url}/realms/{realm}'
        )
        print(f"Decoded token: {decoded_token}")

        if decoded_token.get('azp') != client_id:
            return "Unauthorized - Invalid authorized party", 401

        return "Token is valid and verified", 200
    except Exception as e:
        return f"Error: {e}", 401

@app.route('/fiz')
@require_valid_token
def fiz():
    # Token is already validated by decorator
    # You can access the decoded token through request.token
    return "This is a protected fiz endpoint! You are authenticated!", 200

if __name__ == '__main__':
    app.run(port=3000, debug=True)

