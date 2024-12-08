from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
from collections import deque
import time
import uuid
from passlib.hash import argon2

# Generates a secure password using UUIDv4
def generate_secure_password():
    return str(uuid.uuid4())

# Hashes a password using Argon2
def hash_password(password):
    return argon2.using(rounds=4, salt_size=16).hash(password)

# Rate limit parameters
MAX_REQUESTS_PER_SECOND = 10
TIME_WINDOW = 1  # Seconds

# Store timestamps of successful POST requests to /auth
request_timestamps = deque()

# Helper function for rate limiting
def is_rate_limited():
    current_time = time.time()
    
    # Remove timestamps that are older than 1 second from the current time
    while request_timestamps and request_timestamps[0] < current_time - TIME_WINDOW:
        request_timestamps.popleft()

    # If the number of requests in the current time window is greater than the limit
    if len(request_timestamps) >= MAX_REQUESTS_PER_SECOND:
        return True
    else:
        # Otherwise, log the current timestamp
        request_timestamps.append(current_time)
        return False

# Server and port requests are made
hostName = "localhost"
serverPort = 8080

# SQLite database file initialization/creation
def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Create a table if it doesn't exist
    cursor.execute(' CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)')
    conn.commit()
    cursor.execute(' CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)')
    conn.commit()
    cursor.execute(' CREATE TABLE IF NOT EXISTS auth_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))')
    conn.commit()
    return conn

# Database initialization/creation
db_conn = init_db()

# Creation of private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Store the key and its expiration in the database
def store_key(pem, expiration_time):
    cursor = db_conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration_time))
    db_conn.commit()

# Copy of private key to deal with expired scenario
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# PEM encoding of the private key
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# PEM encoding of the copy of the private key
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Assigns numbers with the private numbers of the private key
numbers = private_key.private_numbers()

# Convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')  # Ensure no padding
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    # Controls HTTP PUT requests
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # Controls HTTP PATCH requests
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # Controls HTTP DELETE requests
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # Controls HTTP HEAD requests
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # Controls HTTP POST requests
    def do_POST(self):
        # Check if the request exceeds the rate limit
        if is_rate_limited():
            # Respond with 429 if rate limited
            self.send_response(429)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes("Too Many Requests", "utf-8"))
            return
        
        # Parse the URL path and the query string, and extract query parameters from the URL
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        # Check if the request path is /register
        if self.path == "/register":
            # Get length of data and read based on that length
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Parse JSON body (assuming body is in JSON format)
            try:
                user_data = json.loads(post_data)
            except json.JSONDecodeError:
                # If malformed, send bad request and error message to client
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Invalid JSON format"}), "utf-8"))
                return

            # Get username and email from the request
            username = user_data.get("username")
            email = user_data.get("email")

            # Verifies that both username and email are provided
            if not username or not email:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Username and email are required"}), "utf-8"))
                return

            # Generate a secure password using UUIDv4
            password = generate_secure_password()

            # Hash the password using Argon2
            password_hash = hash_password(password)

            # Store the user details in the "users" table
            cursor = db_conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                               (username, password_hash, email))
                db_conn.commit()
            
            # If insertion fails, send bad response and error message to client
            except sqlite3.IntegrityError as e:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": f"User could not be created: {str(e)}"}), "utf-8"))
                return

            # Return the generated password in the response if user created successfully
            response = {"password": password}
            self.send_response(201)  # HTTP status code 201 Created
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        # Checks if a request is made; if one is made then a payload is prepared with an expiration time and username
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            
            # Handles expired keys
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                # 1 hour in the past
                expiration_time = int(datetime.datetime.utcnow().timestamp()) - 3600
            else:
                # 1 hour from now
                expiration_time = int(datetime.datetime.utcnow().timestamp()) + 3600
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            
            # Store the key in the database with expiration time
            store_key(pem, expiration_time)

            #Respond with JWT token
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        
        # Sends a 405 if the path does not match
        self.send_response(405)
        self.end_headers()
        return
    
    # Controls HTTP GET requests
    def do_GET(self):
        # Checks if a request is made; if one is made, it prepares a JSON response with a public key
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        
        # If the path isn't right, returns a 405
        self.send_response(405)
        self.end_headers()
        return

# Runs the HTTP server
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
