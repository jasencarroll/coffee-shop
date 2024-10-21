import http.client
import json
import jwt
import logging
from urllib.request import urlopen
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# Function to convert JWKS n and e values into a PEM formatted public key
def construct_pem_key(rsa_key):
    """Converts RSA components (n and e) into a PEM-formatted public key."""
    n = int.from_bytes(base64.urlsafe_b64decode(rsa_key['n'] + '=='), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(rsa_key['e'] + '=='), 'big')

    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Function to get the RSA key from Auth0's JWKS
def get_rsa_key(token, auth0_domain):
    """Fetches the RSA key for decoding the JWT token."""
    try:
        # Fetch JWKS from Auth0
        jwks_url = f"https://{auth0_domain}/.well-known/jwks.json"
        print(f"Fetching JWKS from: {jwks_url}")
        jsonurl = urlopen(jwks_url)
        jwks = json.loads(jsonurl.read())
        print(f"JWKS fetched: {jwks}")
    except Exception as e:
        print(f"Error fetching JWKS: {e}")
        raise Exception("JWKS fetch error")

    # Find the correct key based on the 'kid'
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = next(
        (key for key in jwks["keys"] if key["kid"] == unverified_header["kid"]), 
        None
    )

    if rsa_key:
        return construct_pem_key(rsa_key)

    raise Exception("Unable to find appropriate key")

# Step 1: Get the access token
def get_access_token():
    conn = http.client.HTTPSConnection("dev-8his2amisscpohz8.us.auth0.com")

    # Define the payload for the token request
    payload = json.dumps({
        "client_id": "crdEueHkd1qDu7VaRhM1vdrFrfkNQdSY",
        "client_secret": "_jkB6Kup0wD70cRPO3XD0ue9Sulp62qmrbIeYdKKjL1Ia8McxlO42wfh8k0BZI_j",
        "audience": "https://jcscoffeeshop510698.com",
        "grant_type": "client_credentials"
    })

    headers = { 'Content-Type': "application/json" }

    # Make the POST request to obtain the token
    conn.request("POST", "/oauth/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    token_data = json.loads(data.decode("utf-8"))

    # Print the access token (if needed)
    print(f"Access Token: {token_data['access_token']}")
    
    return token_data['access_token']

# Step 2: Validate the token using JWKS and decode it
def validate_and_decode_token(token):
    auth0_domain = "dev-8his2amisscpohz8.us.auth0.com"
    rsa_key_pem = get_rsa_key(token, auth0_domain)

    try:
        # Decode and validate the JWT token using the RSA key in PEM format
        decoded_payload = jwt.decode(
            token,
            rsa_key_pem,
            algorithms=['RS256'],
            audience="https://jcscoffeeshop510698.com",
            issuer=f"https://{auth0_domain}/"
        )
        print("\n\n" + token + "\n\n")
        print("Token is valid. Decoded payload:")
        print(decoded_payload)
    except ExpiredSignatureError:
        print("Error: Token is expired")
    except InvalidAudienceError:
        print("Error: Invalid audience")
    except InvalidIssuerError:
        print("Error: Invalid issuer")
    except Exception as e:
        print(f"Token validation error: {e}")
        
    if decoded_payload:
        # JWT (Bearer) token provided
        token_with_bear = "Bearer " + token
        headers = {
            'authorization': token_with_bear
        }
        try:
            conn = http.client.HTTPConnection("localhost:5000")
            conn.request("GET", "/api/private", headers=headers)
            res = conn.getresponse()
            data = res.read()
            print(data.decode("utf-8"))
        except Exception as e:
            logging.error(f"Error during HTTP request: {e}")



# Main execution flow
if __name__ == "__main__":
    # Fetch the access token
    access_token = get_access_token()

    # Validate the token and decode it
    validate_and_decode_token(access_token)
