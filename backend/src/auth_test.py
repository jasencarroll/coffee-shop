import unittest
import json
from api import app

class AuthTestCase(unittest.TestCase):

    def setUp(self):
        """Set up the app and test client."""
        self.app = app
        self.client = self.app.test_client()
        self.headers = {
            'Authorization': f'Bearer {mock_jwt}'
        }

    def test_public_endpoint(self):
        """Test public endpoint that doesn't require authentication."""
        response = self.client.get('/api/public')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a public endpoint!', response.data)

    def test_private_endpoint_without_auth(self):
        """Test private endpoint that requires authentication but no token is provided."""
        response = self.client.get('/api/private')
        self.assertEqual(response.status_code, 401)

    def test_private_endpoint_with_auth(self):
        """Test private endpoint with a valid token."""
        response = self.client.get('/api/private', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a private endpoint!', response.data)

    def test_private_scoped_endpoint_with_valid_scope(self):
        """Test private scoped endpoint with a valid token and scope."""
        response = self.client.get('/api/private-scoped', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello from a private endpoint!', response.data)

    def test_private_scoped_endpoint_without_valid_scope(self):
        """Test private scoped endpoint without the required scope."""
        response = self.client.get('/api/private-scoped', headers=self.headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'Unauthorized', response.data)

if __name__ == "__main__":
    unittest.main()