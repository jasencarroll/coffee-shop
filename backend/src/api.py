import os
from flask import Flask, jsonify, request, json
from dotenv import load_dotenv
from flask_cors import CORS
from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import requires_auth

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

# Initialize Flask app and set up CORS
app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()
##############################################################################
# ERROR HANDLING #############################################################
##############################################################################

'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''

# Ensure that AuthError inherits from Exception
class AuthError(Exception):
    """Custom Exception for Authentication Errors."""
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Error handler for authentication errors."""
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

##############################################################################
# ROUTES #####################################################################
##############################################################################

@app.route("/api/public")
def public():
    """Public endpoint that does not require authentication."""
    return jsonify(message="Hello from a public endpoint! No authentication required.")

@app.route("/api/private")
@requires_auth()  # No permission specified here
def private():
    """Private endpoint that requires authentication."""
    return jsonify(message="Hello from a private endpoint! Authentication required.")

##############################################################################
# COFFEE SHOP ################################################################
##############################################################################

'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods=['GET'])
def get_drinks():
    try:
        # Query all drinks from the database
        drinks = Drink.query.all()
        print(drinks)

        # Convert each drink to its short form
        drinks_short = [drink.short() for drink in drinks]

        # Return the success response with status code 200
        return jsonify({
            "success": True,
            "drinks": drinks_short
        }), 200

    except Exception as e:
        # Catch any exception that occurs and return a general error response
        print(f"Error: {str(e)}")  # Log the error for debugging purposes
        return jsonify({
            "success": False,
            "error": "An unexpected error occurred. Please try again later."
        }), 500

'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
# Secret key used for decoding the JWT (in a real app, you'd get this from a secure config)
SECRET_KEY = CLIENT_SECRET  # Replace with your actual Auth0 secret
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('')  # Ensure the 'get:drinks-detail' permission is required
def get_drinks_detail():
    try:
        # Query all drinks from the database
        drinks = Drink.query.all()

        # Convert each drink to its long form
        drinks_long = [drink.long() for drink in drinks]

        # Return the success response with status code 200
        return jsonify({
            "success": True,
            "drinks": drinks_long
        }), 200

    except Exception as e:
        # Catch any exception that occurs and return a general error response
        print(f"Error: {str(e)}")  # Log the error for debugging purposes
        return jsonify({
            "success": False,
            "error": "An unexpected error occurred. Please try again later."
        }), 500

'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')  # Requires the 'post:drinks' permission
def create_drink():
    try:
        # Get the JSON data from the request body
        body = request.get_json()

        # Validate the input data
        if not body or 'title' not in body or 'recipe' not in body:
            return jsonify({
                "success": False,
                "error": "Invalid input, title and recipe are required."
            }), 400  # Bad Request

        title = body['title']
        recipe = json.dumps(body['recipe'])  # Convert recipe (dict) to a JSON string

        # Create a new drink object
        new_drink = Drink(title=title, recipe=recipe)

        # Insert the new drink into the database
        new_drink.insert()

        # Return the long() representation of the newly created drink
        return jsonify({
            "success": True,
            "drinks": [new_drink.long()]
        }), 200

    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error: {str(e)}")

        # Return a general error message
        return jsonify({
            "success": False,
            "error": "An error occurred while creating the drink."
        }), 500  # Internal Server Error


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')  # Requires the 'patch:drinks' permission
def update_drink(id):
    try:
        # Fetch the drink from the database by ID
        drink = Drink.query.get(id)

        # If the drink with the given ID does not exist, return a 404 error
        if drink is None:
            return jsonify({
                "success": False,
                "error": "Drink not found."
            }), 404  # Not Found

        # Get the JSON data from the request body
        body = request.get_json()

        # Check if there is data to update, and apply changes if needed
        if 'title' in body:
            drink.title = body['title']
        if 'recipe' in body:
            # Convert the recipe to a JSON string before saving it to the database
            drink.recipe = json.dumps(body['recipe'])

        # Commit the updates to the database
        drink.update()

        # Return the updated drink in the long format
        return jsonify({
            "success": True,
            "drinks": [drink.long()]
        }), 200

    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error: {str(e)}")

        # Return a general error message
        return jsonify({
            "success": False,
            "error": "An error occurred while updating the drink."
        }), 500  # Internal Server Error

'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')  # Requires the 'delete:drinks' permission
def delete_drink(id):
    try:
        # Fetch the drink from the database by ID
        drink = Drink.query.get(id)

        # If the drink with the given ID does not exist, return a 404 error
        if drink is None:
            return jsonify({
                "success": False,
                "error": "Drink not found."
            }), 404  # Not Found

        # Delete the drink from the database
        drink.delete()

        # Return success response with the ID of the deleted drink
        return jsonify({
            "success": True,
            "delete": id
        }), 200

    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error: {str(e)}")

        # Return a general error message
        return jsonify({
            "success": False,
            "error": "An error occurred while deleting the drink."
        }), 500  # Internal Server Error

# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404
'''

# 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": "internal server error"
    }), 500

# 400 Bad Request Error
@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "bad request"
    }), 400

# 405 Method Not Allowed Error
@app.errorhandler(405)
def method_not_allowed_error(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": "method not allowed"
    }), 405

# General error handler for unhandled exceptions
@app.errorhandler(Exception)
def unhandled_exception(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": "an unexpected error occurred"
    }), 500
    
'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''

# 404 Not Found Error
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404

