import unittest
import threading
import time
import os
import random
import string

from modules.ChatClient import ChatClient
from server import ChatServer
from modules.config import HOST, PORT, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

class TestChatApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Start the chat server in a background thread. 
        This runs once before all tests.
        """
        # Ensure no leftover DB from a previous test run
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

        cls.server = ChatServer(
            host=HOST,
            port=PORT,
            db_file=DB_FILE,
            cert_file=CERT_FILE,
            key_file=KEY_FILE,
            log_file=LOG_FILE
        )
        
        # Start server in a separate thread
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()

        # Give the server a moment to set up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        """
        Clean up after all tests have run.
        """
        # Stop the server gracefully
        cls.server.stop()
        cls.server_thread.join(timeout=5)
        
        # Clean up the test DB
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

    def test_register_login_message(self):
        """
        End-to-end test that verifies:
          1. A user can register
          2. The same user can login
          3. The user can send a message once logged in
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        # Generate a random username to avoid collisions
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        test_password = "testpass"
        
        # 1) Register
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Registration failed: {resp}")

        # 2) Login
        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed: {resp}")
        self.assertIn("session_id", resp, "No session_id returned on login")

        # 3) Send a message
        message_text = "Hello, World!"
        resp = client.send_request(
            action="message",
            from_user=test_username,
            to_user="anotheruser",  # Just an example; server prints it to console
            password="",            # Not needed here once logged in
            msg=message_text
        )
        self.assertEqual(resp.get("status"), "ok", f"Message send failed: {resp}")
        self.assertIn("Message delivered", resp.get("message", ""), "Unexpected message response")

        # Optional: Confirm that the client's stored session matches
        self.assertIsNotNone(client.session_id, "Client did not store session_id")

    '''
    Test error handling:
    - Log in with nonexistent username (e.g. test if can login before registering a username)
    - Try to create same username twice
    - Login with incorrect password
    - Send a message to a user that does not exist
    '''
        

if __name__ == "__main__":
    unittest.main()