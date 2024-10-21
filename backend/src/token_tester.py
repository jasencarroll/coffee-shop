import http.client
import json
import logging
from jwt import decode, PyJWKClient, exceptions

# Initialize logging for error tracing
logging.basicConfig(level=logging.DEBUG)

# Set up the connection
conn = http.client.HTTPConnection("localhost:5000")

# JWT (Bearer) token provided
token = ("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImlWRjJhazVKX1JlSGlXdDl1Qm5mcSJ9.eyJpc3MiOiJodHRwczovL2Rldi04aGlzMmFtaXNzY3BvaHo4LnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJjcmRFdWVIa2QxcUR1N1ZhUmhNMXZkckZyZmtOUWRTWUBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9qY3Njb2ZmZWVzaG9wNTEwNjk4LmNvbSIsImlhdCI6MTcyOTU0MTAwNCwiZXhwIjoxNzI5NjI3NDA0LCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMiLCJhenAiOiJjcmRFdWVIa2QxcUR1N1ZhUmhNMXZkckZyZmtOUWRTWSJ9.GtaxT9RheGAvsy2gnOP7htO8JHNO36af6chOACoMnKlrsycdoFfkpocI4JwRwtd9RHq6RPld4mrbiag0PIJS-ChLD1qJ_W7_CKH_q5zu0O0AIdgSgq90IYmal4jCu0cAzEqMHfseqkjx0TzK16eWigYYj5wxaXNihwPun1rb3jjUT0uG43OFrGzl6MGGI0N9X3l8fY8NiIfPH6Q11N555z9rysIQqeUJrilNkMBHdDdEMOTILDCjroKIweNV6IQJgUWBpTaPocI79fNyK8CHhBO0FjqufJDv5_xi8S2xhdoh2B-dlqE22-ffRd5RYlcnEs-fyZckolEV1m2n1oyg_w")

headers = {
    'authorization': token
}

# Endpoint for the Auth0 JWKS
jwks_url = "https://dev-8his2amisscpohz8.us.auth0.com/.well-known/jwks.json"

try:
    conn.request("GET", "/api/private", headers=headers)
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))
except Exception as e:
    logging.error(f"Error during HTTP request: {e}")
