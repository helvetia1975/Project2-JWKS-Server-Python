import unittest
import requests
import json
import time

class TestMyServer(unittest.TestCase):
    BASE_URL = 'http://localhost:8080'

    @classmethod
    # Start the server here if needed or ensure it's running
    def setUpClass(cls):
        pass

    # Shut down the server if you started it in setUpClass
    @classmethod
    def tearDownClass(cls):
        pass

    # Decode and verify the token (you can use jwt.decode with the public key)
    def test_post_auth_success(self):
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.content.decode('utf-8')
        self.assertIsNotNone(token)

    # Decode and verify the expired token
    def test_post_auth_expired(self):
        response = requests.post(f"{self.BASE_URL}/auth?expired=1")
        self.assertEqual(response.status_code, 200)
        token = response.content.decode('utf-8')
        self.assertIsNotNone(token)
    # Send a GET request to get the JWKS; confirms that the returned code is 200
    def test_get_jwks(self):
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = json.loads(response.content)
        self.assertIn('keys', keys)
        self.assertGreater(len(keys['keys']), 0)
    # Send a DELETE request to /auth endpoint; confirms that the returned code is 405
    def test_invalid_method(self):
        response = requests.delete(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 405)
    # Send a GET request to an invalid path; confirms that the returned code is 405
    def test_invalid_path(self):
        response = requests.get(f"{self.BASE_URL}/invalid_path")
        self.assertEqual(response.status_code, 405)

if __name__ == '__main__':
    unittest.main()
