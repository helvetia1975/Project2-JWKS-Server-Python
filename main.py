from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Server and port requests are made to
hostName = "localhost"
serverPort = 8080

# SQLite database file initialization/creation
def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    # Create a table if it doesn't exist
    cursor.execute(' CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL')
    conn.commit()  # Save changes
    return conn  # Return the connection object

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
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
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
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
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
                expiration_time = int(datetime.datetime.utcnow().timestamp()) - 3600  # 1 hour in the past
            else:
                expiration_time = int(datetime.datetime.utcnow().timestamp()) + 3600  # 1 hour from now
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            
            # Store the key in the database with expiration time
            store_key(pem, expiration_time)

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
    db_conn.close()