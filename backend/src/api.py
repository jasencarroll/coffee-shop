import os
import jwt
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from urllib.request import urlopen
from flask import Flask, request, jsonify, abort, _request_ctx_stack
from sqlalchemy import exc
import json
from flask_cors import CORS, cross_origin
from functools import wraps

#from .database.models import db_drop_and_create_all, setup_db, Drink

# AUTH VARIABLES
##############################################################################
AUTH0_DOMAIN = 'dev-i6mkw7r670gmhfzt.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://jcscoffeeshop510699.com/auth/api'

# APP SETUP
##############################################################################
app = Flask(__name__)
#setup_db(app)
CORS(app)

# db_drop_and_create_all()

# AUTH
##############################################################################
# Error Handling
##############################################################################
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# AUTH
##############################################################################
# Format error response and append status code
##############################################################################
def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token

def requires_auth(f):
    """Determines if the Access Token is valid"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()

        # Fetch JWKS from Auth0
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())

        # Get unverified header from the token
        unverified_header = jwt.get_unverified_header(token)
        
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        
        if rsa_key:
            try:
                # Decode the JWT and verify claims
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "Token is expired"}, 401)
            except InvalidAudienceError:
                raise AuthError({"code": "invalid_audience",
                                 "description": "Invalid audience"}, 401)
            except InvalidIssuerError:
                raise AuthError({"code": "invalid_issuer",
                                 "description": "Invalid issuer"}, 401)
            except Exception as e:
                raise AuthError({"code": "invalid_header",
                                 "description": "Unable to parse authentication token"}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)

        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)
    
    return decorated

# Auth0 Python SDK

def requires_scope(required_scope):
    """Determines if the required scope is present in the Access Token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
            token_scopes = unverified_claims["scope"].split()
            for token_scope in token_scopes:
                if token_scope == required_scope:
                    return True
    return False
# Controllers API

# FAKE ROUTES FOR TESTING
##############################################################################
# This doesn't need authentication
@app.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)

# This needs authentication
@app.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private():
    response = "Hello from a private endpoint! You need to be authenticated to see this."
    return jsonify(message=response)

# This needs authorization
@app.route("/api/private-scoped")
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def private_scoped():
    if requires_scope("read:messages"):
        response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
        return jsonify(message=response)
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)

