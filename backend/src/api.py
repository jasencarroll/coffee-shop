import os
import jwt
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS
from functools import wraps
from dotenv import load_dotenv
import jwt
from jwt import exceptions as jwt_exceptions
import requests


#from .database.models import db_drop_and_create_all, setup_db, Drink

##############################################################################
# APPLICATION SETUP ##########################################################
##############################################################################

# Load environment variables from a .env file for test
load_dotenv()

# Configuration variables (ensure these are set in your environment or .env file)
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
API_AUDIENCE = os.getenv('API_AUDIENCE')
ALGORITHMS = ['RS256']
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

app = Flask(__name__)
#setup_db(app)
CORS(app)

# db_drop_and_create_all()

# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

##############################################################################
# AUTH #######################################################################
##############################################################################

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

# def requires_scope(required_scope):
#     """Determines if the required scope is present in the Access Token
#     Args:
#         required_scope (str): The scope required to access the resource
#     """
#     token = get_token_auth_header()
#     unverified_claims = jwt.get_unverified_claims(token)
#     if unverified_claims.get("scope"):
#             token_scopes = unverified_claims["scope"].split()
#             for token_scope in token_scopes:
#                 if token_scope == required_scope:
#                     return True
#     return False

##############################################################################
# ROUTES #####################################################################
##############################################################################

# Controllers API

# This doesn't need authentication
@app.route("/api/public")
def public():
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)

# This needs authentication
@app.route("/api/private")
@requires_auth
def private():
    response = "Hello from a private endpoint! You need to be authenticated to see this."
    return jsonify(message=response)

# This needs authorization
@app.route("/api/private-scoped")
@requires_auth
def private_scoped():
    # if requires_scope("read:messages"):
    #     response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
    #     return jsonify(message=response)
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)

##############################################################################
# GET TOKEN FOR TESTING ######################################################
##############################################################################

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

##############################################################################
# TDD ########################################################################
##############################################################################
# Unit tests using Test-Driven Development approach
import unittest
from unittest.mock import patch

# Unit tests using Test-Driven Development approach
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

    def test_private_endpoint_with_token(self):
        """Test accessing the private endpoint with a valid token."""
        token = get_access_token()
        headers = {'Authorization': f'Bearer {token}'}
        response = self.client.get('/private', headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a private endpoint', response.data)

##############################################################################
# Initialize Server, needs flask run to get db ###############################
##############################################################################

if __name__ == '__main__':
    import sys
    if 'test' in sys.argv:
        # Run the tests
        unittest.main(argv=['first-arg-is-ignored'])
    else:
        # Start the Flask server
        app.run(debug=True)


##############################################################################
##############################################################################
##############################################################################

# # ROUTES
# '''
# @TODO implement endpoint
#     GET /drinks
#         it should be a public endpoint
#         it should contain only the drink.short() data representation
#     returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
#         or appropriate status code indicating reason for failure
# '''
# @app.route('/drinks', methods=['GET'])
# def get_drinks():
#     try:
#         # Query all drinks from the database
#         drinks = Drink.query.all()
#         print(drinks)

#         # Convert each drink to its short form
#         drinks_short = [drink.short() for drink in drinks]

#         # Return the success response with status code 200
#         return jsonify({
#             "success": True,
#             "drinks": drinks_short
#         }), 200

#     except Exception as e:
#         # Catch any exception that occurs and return a general error response
#         print(f"Error: {str(e)}")  # Log the error for debugging purposes
#         return jsonify({
#             "success": False,
#             "error": "An unexpected error occurred. Please try again later."
#         }), 500

# '''
# @TODO implement endpoint
#     GET /drinks-detail
#         it should require the 'get:drinks-detail' permission
#         it should contain the drink.long() data representation
#     returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
#         or appropriate status code indicating reason for failure
# '''
# SECRET_KEY = os.getenv('CLIENT_SECRET')

# # Function to check user permission
# def check_user_permission(required_permission):
#     # Get the Authorization header from the request
#     auth_header = request.headers.get('Authorization', None)
    
#     if not auth_header:
#         # No authorization header, permission check fails
#         return False
    
#     # Authorization header format: "Bearer <JWT>"
#     token_parts = auth_header.split()

#     if token_parts[0].lower() != 'bearer' or len(token_parts) != 2:
#         # Invalid token format
#         return False
    
#     token = token_parts[1]

#     try:
#         # Decode the JWT token to extract its contents (permissions claim)
#         payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
#         # Extract permissions from the token's payload
#         permissions = payload.get('permissions', [])
        
#         # Check if the required permission is in the user's permissions
#         if required_permission in permissions:
#             return True
#         else:
#             return False

#     except jwt.ExpiredSignatureError:
#         # Token has expired
#         print("Token has expired")
#         return False
#     except jwt.InvalidTokenError:
#         # Token is invalid for any other reason
#         print("Invalid token")
#         return False

# # Decorator that ensures the user has the correct permissions
# def requires_permission(permission):
#     def decorator(f):
#         @wraps(f)
#         def wrapper(*args, **kwargs):
#             # This method will check permissions (implementation may vary)
#             if not check_user_permission(permission):  # You should implement this function based on your auth logic
#                 return jsonify({
#                     "success": False,
#                     "error": "Permission not found."
#                 }), 403  # Forbidden if the permission is missing
#             return f(*args, **kwargs)
#         return wrapper
#     return decorator

# @app.route('/drinks-detail', methods=['GET'])
# #@requires_auth('get:drinks-detail')  # Ensure the 'get:drinks-detail' permission is required
# def get_drinks_detail():
#     try:
#         # Query all drinks from the database
#         drinks = Drink.query.all()

#         # Convert each drink to its long form
#         drinks_long = [drink.long() for drink in drinks]

#         # Return the success response with status code 200
#         return jsonify({
#             "success": True,
#             "drinks": drinks_long
#         }), 200

#     except Exception as e:
#         # Catch any exception that occurs and return a general error response
#         print(f"Error: {str(e)}")  # Log the error for debugging purposes
#         return jsonify({
#             "success": False,
#             "error": "An unexpected error occurred. Please try again later."
#         }), 500

# '''
# @TODO implement endpoint
#     POST /drinks
#         it should create a new row in the drinks table
#         it should require the 'post:drinks' permission
#         it should contain the drink.long() data representation
#     returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
#         or appropriate status code indicating reason for failure
# '''

# @app.route('/drinks', methods=['POST'])
# @requires_auth('post:drinks')  # Requires the 'post:drinks' permission
# def create_drink():
#     try:
#         # Get the JSON data from the request body
#         body = request.get_json()

#         # Validate the input data
#         if not body or 'title' not in body or 'recipe' not in body:
#             return jsonify({
#                 "success": False,
#                 "error": "Invalid input, title and recipe are required."
#             }), 400  # Bad Request

#         title = body['title']
#         recipe = json.dumps(body['recipe'])  # Convert recipe (dict) to a JSON string

#         # Create a new drink object
#         new_drink = Drink(title=title, recipe=recipe)

#         # Insert the new drink into the database
#         new_drink.insert()

#         # Return the long() representation of the newly created drink
#         return jsonify({
#             "success": True,
#             "drinks": [new_drink.long()]
#         }), 200

#     except Exception as e:
#         # Log the error for debugging purposes
#         print(f"Error: {str(e)}")

#         # Return a general error message
#         return jsonify({
#             "success": False,
#             "error": "An error occurred while creating the drink."
#         }), 500  # Internal Server Error


# '''
# @TODO implement endpoint
#     PATCH /drinks/<id>
#         where <id> is the existing model id
#         it should respond with a 404 error if <id> is not found
#         it should update the corresponding row for <id>
#         it should require the 'patch:drinks' permission
#         it should contain the drink.long() data representation
#     returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
#         or appropriate status code indicating reason for failure
# '''

# @app.route('/drinks/<int:id>', methods=['PATCH'])
# @requires_auth('patch:drinks')  # Requires the 'patch:drinks' permission
# def update_drink(id):
#     try:
#         # Fetch the drink from the database by ID
#         drink = Drink.query.get(id)

#         # If the drink with the given ID does not exist, return a 404 error
#         if drink is None:
#             return jsonify({
#                 "success": False,
#                 "error": "Drink not found."
#             }), 404  # Not Found

#         # Get the JSON data from the request body
#         body = request.get_json()

#         # Check if there is data to update, and apply changes if needed
#         if 'title' in body:
#             drink.title = body['title']
#         if 'recipe' in body:
#             # Convert the recipe to a JSON string before saving it to the database
#             drink.recipe = json.dumps(body['recipe'])

#         # Commit the updates to the database
#         drink.update()

#         # Return the updated drink in the long format
#         return jsonify({
#             "success": True,
#             "drinks": [drink.long()]
#         }), 200

#     except Exception as e:
#         # Log the error for debugging purposes
#         print(f"Error: {str(e)}")

#         # Return a general error message
#         return jsonify({
#             "success": False,
#             "error": "An error occurred while updating the drink."
#         }), 500  # Internal Server Error

# '''
# @TODO implement endpoint
#     DELETE /drinks/<id>
#         where <id> is the existing model id
#         it should respond with a 404 error if <id> is not found
#         it should delete the corresponding row for <id>
#         it should require the 'delete:drinks' permission
#     returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
#         or appropriate status code indicating reason for failure
# '''

# @app.route('/drinks/<int:id>', methods=['DELETE'])
# @requires_auth('delete:drinks')  # Requires the 'delete:drinks' permission
# def delete_drink(id):
#     try:
#         # Fetch the drink from the database by ID
#         drink = Drink.query.get(id)

#         # If the drink with the given ID does not exist, return a 404 error
#         if drink is None:
#             return jsonify({
#                 "success": False,
#                 "error": "Drink not found."
#             }), 404  # Not Found

#         # Delete the drink from the database
#         drink.delete()

#         # Return success response with the ID of the deleted drink
#         return jsonify({
#             "success": True,
#             "delete": id
#         }), 200

#     except Exception as e:
#         # Log the error for debugging purposes
#         print(f"Error: {str(e)}")

#         # Return a general error message
#         return jsonify({
#             "success": False,
#             "error": "An error occurred while deleting the drink."
#         }), 500  # Internal Server Error

# # Error Handling
# '''
# Example error handling for unprocessable entity
# '''


# @app.errorhandler(422)
# def unprocessable(error):
#     return jsonify({
#         "success": False,
#         "error": 422,
#         "message": "unprocessable"
#     }), 422


# '''
# @TODO implement error handlers using the @app.errorhandler(error) decorator
#     each error handler should return (with approprate messages):
#              jsonify({
#                     "success": False,
#                     "error": 404,
#                     "message": "resource not found"
#                     }), 404
# '''

# # 500 Internal Server Error
# @app.errorhandler(500)
# def internal_server_error(error):
#     return jsonify({
#         "success": False,
#         "error": 500,
#         "message": "internal server error"
#     }), 500

# # 400 Bad Request Error
# @app.errorhandler(400)
# def bad_request_error(error):
#     return jsonify({
#         "success": False,
#         "error": 400,
#         "message": "bad request"
#     }), 400

# # 405 Method Not Allowed Error
# @app.errorhandler(405)
# def method_not_allowed_error(error):
#     return jsonify({
#         "success": False,
#         "error": 405,
#         "message": "method not allowed"
#     }), 405

# # General error handler for unhandled exceptions
# @app.errorhandler(Exception)
# def unhandled_exception(error):
#     return jsonify({
#         "success": False,
#         "error": 500,
#         "message": "an unexpected error occurred"
#     }), 500
    
# '''
# @TODO implement error handler for 404
#     error handler should conform to general task above
# '''

# # 404 Not Found Error
# @app.errorhandler(404)
# def not_found_error(error):
#     return jsonify({
#         "success": False,
#         "error": 404,
#         "message": "resource not found"
#     }), 404


# '''
# @TODO implement error handler for AuthError
#     error handler should conform to general task above
# '''
# class AuthError(Exception):
#     def __init__(self, error, status_code):
#         super().__init__(error)
#         self.error = error
#         self.status_code = status_code

# # Example route that could raise an AuthError
# @app.route('/protected')
# def protected_route():
#     # Simulate an authorization failure (e.g., missing token or insufficient permissions)
#     raise AuthError({
#         'code': 'unauthorized',
#         'description': 'Permission not found.'
#     }, 403)

# # AuthError handler
# @app.errorhandler(AuthError)
# def handle_auth_error(error):
#     response = jsonify({
#         "success": False,
#         "error": error.status_code,
#         "message": error.error['description']
#     })
#     return response, error.status_code