from flask import Flask, redirect, request, session, url_for, jsonify
import requests
import secrets
import os
import urllib.parse

# Flask app setup
app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Keycloak settings (Replace these values with your own)
keycloak_url = 'http://localhost:8080'
realm = os.getenv('REALM')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
redirect_uri = 'http://localhost:3000/callback'

# Authorization URL for Keycloak
authorization_url = f'{keycloak_url}/realms/{realm}/protocol/openid-connect/auth'
token_url = f'{keycloak_url}/realms/{realm}/protocol/openid-connect/token'
userinfo_url = f'{keycloak_url}/realms/{realm}/protocol/openid-connect/userinfo'

@app.route('/')
def index():
    return 'Welcome to the OIDC Demo with Keycloak! <a href="/login">Login</a>'

@app.route('/login')
def login():
    # Redirect to Keycloak authorization endpoint
    state = secrets.token_urlsafe(16) # In production, this should be random and secure
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state
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

    # Store tokens in session (this is just for demo purposes)
    session['access_token'] = access_token
    session['id_token'] = id_token

    # Fetch user information from the UserInfo endpoint
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(userinfo_url, headers=headers)
    
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        return f"User Info: {userinfo}"
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
    # Get access token from session
    access_token = session.get('access_token')
    print(f"Access token: {access_token}")
    if not access_token:
        return "Unauthorized - Please login first", 401
    
    # Here you would typically make a request to your protected resource
    # using the access token
    return "This is a protected endpoint! You are authenticated!"

if __name__ == '__main__':
    app.run(port=3000, debug=True)

