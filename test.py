from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time
import unittest
import http.server
import threading
import requests
import json
import os
import sys
print(sys.path)
from project2 import private_key_pem, expired_key_pem

# Import the classes and functions from your program
from project2 import create_keys_table, insert_key, get_key, get_keys, MyServer
from project2 import create_keys_table, insert_key, get_key, get_keys, MyServer, private_key_numbers



class TestMyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the HTTP server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def start_server(cls):
        # Start the HTTP server on a separate port for testing
        cls.server = http.server.HTTPServer(('localhost', 8081), MyServer)
        cls.server.serve_forever()

    def setUp(self):
        # Initialize the database and insert test keys
        create_keys_table()
        insert_key(private_key_pem, int(time.time() + 1000))
        insert_key(expired_key_pem, int(time.time() - 1000))

    def test_get_valid_jwt(self):
        response = requests.post("http://localhost:8081/auth")
        self.assertEqual(response.status_code, 200)
        jwt_token = response.text
        # Verify that the token is a valid JWT
        payload = jwt.decode(jwt_token, verify=False)
        self.assertEqual(payload['exp'], private_key_numbers.n)

    def test_get_expired_jwt(self):
        response = requests.post("http://localhost:8081/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        jwt_token = response.text
        # Verify that the token is a valid JWT
        payload = jwt.decode(jwt_token, verify=False)
        self.assertEqual(payload['exp'], private_key_numbers.n)

    def test_get_jwks_endpoint(self):
        response = requests.get("http://localhost:8081/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks_data = response.json()
        self.assertIn("keys", jwks_data)
        self.assertTrue(isinstance(jwks_data["keys"], list))
        self.assertEqual(len(jwks_data["keys"]), 2)  # Two keys in the database

    @classmethod
    def tearDownClass(cls):
        # Shutdown the HTTP server
        cls.server.shutdown()
        cls.server.server_close()

if __name__ == '__main__':
    unittest.main()

