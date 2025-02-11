import unittest
import threading
import time
import os
import random
import string
import socket

from modules.ChatClient import ChatClient
from server import ChatServer
from modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

class TestChatApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Instead of using a fixed port from config, choose a free port for the tests.
        # This prevents "Address already in use" errors when a previous test didn’t fully release the port.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, 0))
            cls.port = s.getsockname()[1]
        print(f"Using test port: {cls.port}")

    def setUp(self):
        """
        Start the chat server in a background thread. 
        This runs before each test.
        """
        # Remove any leftover DB file from previous runs.
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

        self.server = ChatServer(
            host=HOST,
            port=self.__class__.port,
            db_file=DB_FILE,
            cert_file=CERT_FILE,
            key_file=KEY_FILE,
            log_file=LOG_FILE
        )
        
        # Start the server in a background thread.
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        # Wait a bit to let the server initialize.
        time.sleep(1.5)

    def tearDown(self):
        """
        Clean up after each test.
        """
        # Stop the server gracefully.
        try:
            self.server.stop()
        except Exception as e:
            print(f"Error stopping server: {e}")

        # Wait for the server thread to finish.
        self.server_thread.join(timeout=5)
        # Give the OS a little time to fully free the port.
        time.sleep(0.5)

        # Remove the DB file.
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
            except Exception as e:
                print(f"Error removing DB file: {e}")

    def test_register_login_message(self):
        """
        End-to-end test verifying that:
          1. A user can register
          2. The same user can login
          3. The user can send a message after login
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Use random usernames for both sender and recipient.
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        test_password = "testpass"
        test_recipient = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        test_message = "Hello, World!"
        
        # 1) Register both users.
        for user in [test_username, test_recipient]:
            resp = client.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=test_password,
                msg=""
            )
            self.assertEqual(
                resp.get("status"), "ok",
                f"Registration failed for {user}: {resp}"
            )

        # 2) Login with the first user.
        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed: {resp}")
        self.assertIn("session_id", resp, "No session_id returned on login")

        # 3) Send a message.
        resp = client.send_request(
            action="message",
            from_user=test_username,
            to_user=test_recipient,
            password="",
            msg=test_message
        )
        self.assertEqual(resp.get("status"), "ok", f"Message send failed: {resp}")
        self.assertIn("Message delivered", resp.get("message", ""),
                      "Unexpected message response")
        self.assertIsNotNone(client.session_id, "Client did not store session_id")
        print(f"Successfully sent message from {test_username} to {test_recipient}")

    def test_login_nonexistent_user(self):
        """
        Test that logging in with a username that isn’t registered returns an error.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Use a random nonexistent username.
        nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))
        resp = client.send_request(
            action="login",
            from_user=nonexistent_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp.get("status"), "error",
                         "Login should fail with nonexistent username")

    def test_register_same_username(self):
        """
        Test that attempting to register the same username twice fails on the second attempt.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        random_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        # First registration should succeed.
        resp = client.send_request(
            action="register",
            from_user=random_username,
            to_user="",
            password="testpass",
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", "First registration should succeed")
        # Wait a brief moment to ensure the server processes the first request.
        time.sleep(0.2)
        # Second registration with the same username should fail.
        resp = client.send_request(
            action="register",
            from_user=random_username,
            to_user="",
            password="testpass",
            msg=""
        )
        self.assertEqual(resp.get("status"), "error",
                         "Registration should fail when using the same username twice")

if __name__ == "__main__":
    unittest.main()