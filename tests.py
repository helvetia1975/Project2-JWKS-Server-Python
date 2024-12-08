import unittest
from http.server import HTTPServer
from io import BytesIO
from unittest.mock import patch
import json
import sqlite3
import time
import uuid
import jwt
import datetime
from main import MyServer, generate_secure_password, hash_password, is_rate_limited, init_db, store_key  # Import functions from your script


class TestMyServer(unittest.TestCase):

    # Setup method to initialize database and server
    def setUp(self):
        self.db_conn = init_db()
        self.server = HTTPServer(('localhost', 8080), MyServer)
        self.server_thread = patch('threading.Thread', target=self.server.serve_forever)
        self.server_thread.start()

    # Teardown method to stop server after tests
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    # Test password generation function
    def test_generate_secure_password(self):
        password = generate_secure_password()
        self.assertIsInstance(password, str)
        self.assertEqual(len(password), 36)  # UUIDv4 length

    # Test password hashing function
    def test_hash_password(self):
        password = "test_password"
        hashed = hash_password(password)
        self.assertTrue(hashed.startswith("$argon2"))
        self.assertNotEqual(hashed, password)  # Ensure the password is hashed

    # Test rate limiting function
    @patch('time.time', return_value=1000)  # Mock time to control the current time
    def test_is_rate_limited(self):
        # Simulate 10 requests within the time window
        for _ in range(10):
            is_rate_limited()
        self.assertTrue(is_rate_limited())  # 11th request should be rate-limited

    # Test user registration endpoint
    def test_user_registration(self):
        # Prepare the POST data
        user_data = {
            "username": "testuser",
            "email": "test@example.com"
        }
        data = json.dumps(user_data).encode('utf-8')

        # Simulate HTTP POST request to /register
        with patch("http.server.BaseHTTPRequestHandler.rfile", new_callable=BytesIO) as mock_rfile:
            mock_rfile.write(data)
            mock_rfile.seek(0)

            with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
                with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                    self.server.handle_request()
                    # Ensure 201 status code is returned
                    mock_send_response.assert_called_with(201)
                    # Ensure response contains the password
                    mock_wfile.write.assert_called()

    # Test /auth endpoint with valid JWT
    def test_auth_valid(self):
        user_data = {"username": "testuser", "email": "test@example.com"}
        data = json.dumps(user_data).encode('utf-8')

        # Prepare request to /auth
        with patch("http.server.BaseHTTPRequestHandler.rfile", new_callable=BytesIO) as mock_rfile:
            mock_rfile.write(data)
            mock_rfile.seek(0)

            with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
                with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                    self.server.handle_request()
                    mock_send_response.assert_called_with(200)
                    mock_wfile.write.assert_called()

    # Test /auth endpoint with expired JWT
    def test_auth_expired(self):
        user_data = {"username": "testuser", "email": "test@example.com"}
        data = json.dumps(user_data).encode('utf-8')

        # Prepare request to /auth with expired param
        with patch("http.server.BaseHTTPRequestHandler.rfile", new_callable=BytesIO) as mock_rfile:
            mock_rfile.write(data)
            mock_rfile.seek(0)

            with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
                with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                    self.server.handle_request()
                    mock_send_response.assert_called_with(200)
                    mock_wfile.write.assert_called()

    # Test user registration with missing data
    def test_user_registration_missing_data(self):
        user_data = {"username": "testuser"}  # Missing email
        data = json.dumps(user_data).encode('utf-8')

        with patch("http.server.BaseHTTPRequestHandler.rfile", new_callable=BytesIO) as mock_rfile:
            mock_rfile.write(data)
            mock_rfile.seek(0)

            with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
                with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                    self.server.handle_request()
                    mock_send_response.assert_called_with(400)
                    mock_wfile.write.assert_called_with(b'{"error": "Username and email are required"}')

    # Test invalid JSON format for registration
    def test_invalid_json_format(self):
        invalid_json = '{"username": "testuser", "email": "test@example.com"'  # Missing closing brace
        data = invalid_json.encode('utf-8')

        with patch("http.server.BaseHTTPRequestHandler.rfile", new_callable=BytesIO) as mock_rfile:
            mock_rfile.write(data)
            mock_rfile.seek(0)

            with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
                with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                    self.server.handle_request()
                    mock_send_response.assert_called_with(400)
                    mock_wfile.write.assert_called_with(b'{"error": "Invalid JSON format"}')

    # Test the /jwks.json endpoint
    def test_jwks_json(self):
        with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
            with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                self.server.handle_request()
                mock_send_response.assert_called_with(200)
                mock_wfile.write.assert_called()

    # Test unsupported HTTP methods
    def test_unsupported_method(self):
        with patch("http.server.BaseHTTPRequestHandler.send_response") as mock_send_response:
            with patch("http.server.BaseHTTPRequestHandler.wfile") as mock_wfile:
                self.server.handle_request()
                mock_send_response.assert_called_with(405)
                mock_wfile.write.assert_called_with(b'{}')

if __name__ == '__main__':
    unittest.main()
