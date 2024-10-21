import os
import jwt
import urllib.request
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, abort
from functools import wraps
from dotenv import load_dotenv

##############################################################################
# APPLICATION SETUP ##########################################################
##############################################################################

# Load environment variables from a .env file
load_dotenv()

# Configuration variables
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
API_AUDIENCE = os.getenv('API_AUDIENCE')
ALGORITHMS = ['RS256']
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

##############################################################################
# AUTH HELPERS ###############################################################
##############################################################################

def get_token_auth_header():
    """Extracts the Access Token from the Authorization Header."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        abort(401, 'Authorization header is missing.')
    
    parts = auth.split()
    
    if parts[0].lower() != 'bearer':
        abort(401, 'Authorization header must start with Bearer.')
    elif len(parts) == 1:
        abort(401, 'Token not found.')
    elif len(parts) > 2:
        abort(401, 'Authorization header must be Bearer token.')

    return parts[1]

def get_rsa_pem(n, e):
    """Convert the JWKS 'n' and 'e' values to an RSA public key in PEM format."""
    # Decode the base64url-encoded modulus and exponent
    n_bytes = base64.urlsafe_b64decode(n + '==')
    e_bytes = base64.urlsafe_b64decode(e + '==')
    
    # Convert bytes to integers
    n_int = int.from_bytes(n_bytes, 'big')
    e_int = int.from_bytes(e_bytes, 'big')
    
    # Create RSA key object
    public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
    
    # Serialize the key to PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem

def verify_decode_jwt(token):
    """Verifies and decodes the JWT token."""
    try:
        # Retrieve the JWKS from Auth0 domain
        jsonurl = urllib.request.urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
        jwks = json.loads(jsonurl.read())
        
        # Get the token header without verification
        unverified_header = jwt.get_unverified_header(token)

        # Find the key that matches the key ID (kid) in the token header
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'n': key['n'],
                    'e': key['e']
                }
                break

        # Validate the token if we found the appropriate RSA key
        if rsa_key:
            pem_key = get_rsa_pem(rsa_key['n'], rsa_key['e'])
            payload = jwt.decode(
                token,
                pem_key,  # Use the converted PEM-formatted key
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f'https://{AUTH0_DOMAIN}/'
            )
            
            # Log or print the payload to check its contents
            print("Decoded JWT Payload: ", payload)
            return payload

    # Error handling for various JWT errors
    except jwt.ExpiredSignatureError:
        abort(401, 'Token expired.')
    except jwt.InvalidAudienceError:
        abort(401, 'Invalid audience. Please check the audience in the token.')
    except jwt.InvalidIssuerError:
        abort(401, 'Invalid issuer. Please check the issuer in the token.')
    except jwt.ImmatureSignatureError:
        abort(401, 'Token is not yet valid (its "nbf" claim is in the future).')
    except jwt.InvalidIssuedAtError:
        abort(401, 'Invalid "iat" claim (issued at time).')
    except jwt.InvalidSignatureError:
        abort(401, 'Invalid token signature.')
    except jwt.DecodeError:
        abort(400, 'Error decoding the token. The token is invalid or malformed.')
    except jwt.MissingRequiredClaimError as e:
        abort(400, f'Missing required claim: {str(e)}.')
    except jwt.InvalidTokenError:
        abort(401, 'Invalid token. General token validation failure.')
    except Exception as e:
        # Generic error handler for any unexpected errors
        abort(400, f'An error occurred while processing the token: {str(e)}')

    # If no RSA key found
    abort(400, 'Unable to find the appropriate key.')

def check_permissions(permission, payload):
    """Checks if the required permission is in the JWT payload."""
    if not permission:
        # If no specific permission is required, allow the request to pass
        return True

    if 'permissions' not in payload:
        abort(400, 'Permissions not included in JWT.')

    if permission not in payload['permissions']:
        abort(403, f'Permission "{permission}" not found in the token.')

    return True

##############################################################################
# AUTH DECORATORS ############################################################
##############################################################################

def requires_auth(permission=''):
    """Decorator for handling authentication and authorization."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(*args, **kwargs)
        return wrapper
    return decorator