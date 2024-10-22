import os
import json
from flask import Flask, jsonify, request, abort
from dotenv import load_dotenv
from flask_cors import CORS
from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import requires_auth
from werkzeug.exceptions import HTTPException

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

@app.route('/drinks', methods=['GET'])
def get_drinks():
    # Query all drinks from the database
    drinks = Drink.query.all()

    # Convert each drink to its short form
    drinks_short = [drink.short() for drink in drinks]

    # Return the success response with status code 200
    return jsonify({
        "success": True,
        "drinks": drinks_short
    }), 200

@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    # Query all drinks from the database
    drinks = Drink.query.all()

    # Convert each drink to its long form
    drinks_long = [drink.long() for drink in drinks]

    # Return the success response with status code 200
    return jsonify({
        "success": True,
        "drinks": drinks_long
    }), 200

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(payload):
    # Get the JSON data from the request body
    body = request.get_json()

    # Validate the input data
    if not body or 'title' not in body or 'recipe' not in body:
        abort(400, description="Invalid input, title and recipe are required.")

    title = body['title']
    recipe = body['recipe']

    # Ensure that recipe is a dict
    if not isinstance(recipe, dict):
        abort(400, description="Recipe must be a dict.")

    # Convert recipe to JSON string
    recipe_json = json.dumps(recipe)

    # Create a new drink object
    new_drink = Drink(title=title, recipe=recipe_json)

    # Insert the new drink into the database
    new_drink.insert()

    # Return the long() representation of the newly created drink
    return jsonify({
        "success": True,
        "drinks": [new_drink.long()]
    }), 200

@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, id):
    # Fetch the drink from the database by ID
    drink = Drink.query.get(id)

    # If the drink with the given ID does not exist, return a 404 error
    if drink is None:
        abort(404, description="Drink not found.")

    # Get the JSON data from the request body
    body = request.get_json()

    if not body:
        abort(400, description="Request does not contain a valid JSON body.")

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

@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('del:drinks')
def delete_drink(payload, id):
    # Fetch the drink from the database by ID
    drink = Drink.query.get(id)

    # If the drink with the given ID does not exist, return a 404 error
    if drink is None:
        abort(404, description="Drink not found.")

    # Delete the drink from the database
    drink.delete()

    # Return success response with the ID of the deleted drink
    return jsonify({
        "success": True,
        "delete": id
    }), 200

# Error Handling
@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return jsonify({
        "success": False,
        "error": error.code,
        "message": error.description,
    }), error.code

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": "An unexpected error occurred."
    }), 500
