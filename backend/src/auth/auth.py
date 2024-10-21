# server.py

import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, request, jsonify
import jwt
from jwt import exceptions as jwt_exceptions
import requests

# Load environment variables from a .env file
load_dotenv()

# Configuration variables (ensure these are set in your environment or .env file)
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
API_AUDIENCE = os.getenv('API_AUDIENCE')
ALGORITHMS = ['RS256']
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

app = Flask(__name__)

def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        return {"code": "authorization_header_missing",
                "description": "Authorization header is expected"}, 401

    parts = auth.split()

    if parts[0].lower() != "bearer":
        return {"code": "invalid_header",
                "description": "Authorization header must start with Bearer"}, 401
    elif len(parts) == 1:
        return {"code": "invalid_header",
                "description": "Token not found"}, 401
    elif len(parts) > 2:
        return {"code": "invalid_header",
                "description": "Authorization header must be Bearer token"}, 401

    token = parts[1]
    return token

def requires_auth(f):
    """Decorator to require authentication on routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        if isinstance(token, tuple):
            return jsonify(token[0]), token[1]

        jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
        jwk_client = jwt.PyJWKClient(jwks_url)

        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f'https://{AUTH0_DOMAIN}/'
            )
        except jwt_exceptions.ExpiredSignatureError:
            return jsonify({"code": "token_expired",
                            "description": "Token is expired"}), 401
        except (jwt_exceptions.InvalidAudienceError, jwt_exceptions.InvalidIssuerError):
            return jsonify({"code": "invalid_claims",
                            "description": "Incorrect claims, please check the audience and issuer"}), 401
        except jwt_exceptions.PyJWTError as e:
            return jsonify({"code": "invalid_header",
                            "description": f"Unable to parse authentication token: {str(e)}"}), 401

        # Token is valid; print it in the terminal
        print(f"Authenticated token: {token}")
        return f(*args, **kwargs)
    return decorated

@app.route('/public')
def public():
    """Public route accessible without authentication."""
    return jsonify(message="Hello from a public endpoint! You don't need to be authenticated to see this.")

@app.route('/private')
@requires_auth
def private():
    """Private route accessible only with valid authentication."""
    return jsonify(message="Hello from a private endpoint! You are authenticated.")

def get_access_token():
    """Obtains an access token from Auth0 using client credentials."""
    url = f'https://{AUTH0_DOMAIN}/oauth/token'
    headers = {'content-type': 'application/json'}
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'audience': API_AUDIENCE
    }
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()
    token = response.json()['access_token']
    return token

# Unit tests using Test-Driven Development approach
import unittest
from unittest.mock import patch

class ServerTestCase(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_public_endpoint(self):
        """Test accessing the public endpoint."""
        response = self.client.get('/public')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a public endpoint', response.data)

    def test_private_endpoint_without_token(self):
        """Test accessing the private endpoint without a token."""
        response = self.client.get('/private')
        self.assertEqual(response.status_code, 401)

    @patch('server.get_access_token')
    @patch('jwt.decode')
    def test_private_endpoint_with_token(self, mock_jwt_decode, mock_get_token):
        """Test accessing the private endpoint with a valid token."""
        mock_get_token.return_value = 'mocked_jwt_token'
        mock_jwt_decode.return_value = {'sub': '1234567890', 'name': 'Test User'}

        headers = {'Authorization': f'Bearer {mock_get_token.return_value}'}
        response = self.client.get('/private', headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a private endpoint', response.data)

if __name__ == '__main__':
    import sys
    if 'test' in sys.argv:
        # Run the tests
        unittest.main(argv=['first-arg-is-ignored'])
    else:
        # Start the Flask server
        app.run(debug=True)
