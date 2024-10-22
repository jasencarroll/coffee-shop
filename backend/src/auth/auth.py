import os
import jwt
import urllib.request
import json
import base64
from flask import request, abort
from functools import wraps
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Load environment variables from a .env file
load_dotenv()

# Configuration variables
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
API_AUDIENCE = os.getenv('API_AUDIENCE')
ALGORITHMS = ['RS256']

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
    jsonurl = urllib.request.urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Get the token header without verification
    unverified_header = jwt.get_unverified_header(token)

    # Choose our key
    rsa_key = {}
    if 'kid' not in unverified_header:
        abort(401, 'Authorization malformed: "kid" not found in token header.')

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
            break

    if rsa_key:
        try:
            # Construct the public key
            pem_key = get_rsa_pem(rsa_key['n'], rsa_key['e'])

            # Decode the token
            payload = jwt.decode(
                token,
                pem_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f'https://{AUTH0_DOMAIN}/'
            )

            # Print the payload for debugging
            print("Decoded JWT Payload:", payload)

            return payload

        except jwt.ExpiredSignatureError:
            abort(401, 'Token expired.')
        except jwt.InvalidAudienceError:
            abort(401, 'Incorrect audience.')
        except jwt.InvalidIssuerError:
            abort(401, 'Incorrect issuer.')
        except jwt.InvalidTokenError as e:
            abort(401, f'Invalid token: {str(e)}')
        except Exception as e:
            abort(400, f'Error decoding token headers: {str(e)}')

    abort(401, 'Unable to find appropriate key.')

def check_permissions(permission, payload):
    """Checks if the required permission is in the JWT payload."""
    if 'permissions' not in payload:
        abort(403, 'Permissions not included in JWT.')

    if permission not in payload['permissions']:
        abort(403, f'Permission "{permission}" not found in token.')

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
            return f(payload, *args, **kwargs)  # Pass payload to the decorated function
        return wrapper
    return decorator
