# Project2-JWKS-Server-Python
This set of files creates JWTS on HTTPS port 8080 using RSA key pairs. Public keys are served on a JWKS endpoint on the server, checking to make sure the keys are good i.e. not expired. The server is being enhanced by a SQLite database file in order to document private keys.

This is my second rendering of this project, this time in Python 3.11. This time around it was successful and I was able to serve the request on the HTTP server, run the gradebot, and create a successful test suite.
