import jwt
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from urllib.request import urlopen
from flask import Flask, request, jsonify, _request_ctx_stack
import json
from flask_cors import CORS, cross_origin
from functools import wraps

# AUTH VARIABLES
##############################################################################
AUTH0_DOMAIN = 'dev-i6mkw7r670gmhfzt.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://jcscoffeeshop510699.com/auth/api'

# APP SETUP
##############################################################################
app = Flask(__name__)
CORS(app)

# AUTH
##############################################################################
# Custom exception class for authentication errors
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Handle authentication errors globally."""
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Helper function to extract token from Authorization header
def get_token_auth_header():
    """Extracts the Access Token from the Authorization Header."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({
            "code": "authorization_header_missing",
            "description": "Authorization header is expected"
        }, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must start with Bearer"
        }, 401)
    elif len(parts) == 1:
        raise AuthError({
            "code": "invalid_header",
            "description": "Token not found"
        }, 401)
    elif len(parts) > 2:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must be Bearer token"
        }, 401)

    return parts[1]

# Helper function to fetch JWKS (JSON Web Key Set) from Auth0
def get_rsa_key(token):
    """Fetches the RSA key for decoding the JWT token."""
    try:
        jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
    except Exception as e:
        raise AuthError({
            "code": "jwks_fetch_error",
            "description": "Error fetching JWKS"
        }, 500)

    unverified_header = jwt.get_unverified_header(token)
    rsa_key = next(
        (key for key in jwks["keys"] if key["kid"] == unverified_header["kid"]), 
        None
    )

    if rsa_key:
        return {
            "kty": rsa_key["kty"],
            "kid": rsa_key["kid"],
            "use": rsa_key["use"],
            "n": rsa_key["n"],
            "e": rsa_key["e"]
        }
    
    raise AuthError({
        "code": "invalid_header",
        "description": "Unable to find appropriate key"
    }, 401)

# Decorator for endpoints that require authentication
def requires_auth(f):
    """Decorator to validate the access token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        rsa_key = get_rsa_key(token)
        
        try:
            # Decode and validate the JWT token
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
            )
        except ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "Token is expired"}, 401)
        except InvalidAudienceError:
            raise AuthError({"code": "invalid_audience", "description": "Invalid audience"}, 401)
        except InvalidIssuerError:
            raise AuthError({"code": "invalid_issuer", "description": "Invalid issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_token", "description": "Invalid token"}, 401)

        # Store the user information in the request context
        _request_ctx_stack.top.current_user = payload
        return f(*args, **kwargs)
    
    return decorated

# Function to verify required scope in JWT token claims
def requires_scope(required_scope):
    """Checks if the required scope is present in the Access Token."""
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)

    if "scope" in unverified_claims:
        token_scopes = unverified_claims["scope"].split()
        if required_scope in token_scopes:
            return True
    return False

# Controllers API (test routes)
##############################################################################

# Public route (no authentication required)
@app.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    return jsonify(message="Hello from a public endpoint! You don't need to be authenticated to see this.")

# Private route (authentication required)
@app.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private():
    return jsonify(message="Hello from a private endpoint! You need to be authenticated to see this.")

# Private route with scope requirement (authentication + authorization required)
@app.route("/api/private-scoped")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private_scoped():
    if requires_scope("read:messages"):
        return jsonify(message="Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.")
    
    raise AuthError({
        "code": "insufficient_scope",
        "description": "You don't have access to this resource"
    }, 403)

