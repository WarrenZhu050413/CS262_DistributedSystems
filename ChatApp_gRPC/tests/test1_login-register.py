import unittest
import time
import random
import string

from ChatApp_gRPC.modules.ChatClient import ChatClient
from ChatApp_gRPC.modules.config import HOST, PORT, CERT_FILE

###############################################################################
# Test Class: Chat Application Tests
###############################################################################
class TestChatApp(unittest.TestCase):
    def test_register_login_send_message(self):
        """
        End-to-end test verifying that:
          1. A user can register
          2. The same user can login
          3. The user can send a message after login
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        # Generate random usernames.
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
            self.assertEqual(resp.get("status"), "ok",
                             f"Registration failed for {user}: {resp}")

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
        self.assertIsNotNone(resp["session_id"], "session_id is None in login response")

        # Store the session ID in the client
        client.session_id = resp["session_id"]

        # 3) Send a message.
        resp = client.send_request(
            action="send_message",
            from_user=test_username,
            to_user=test_recipient,
            password="",
            msg=test_message
        )
        self.assertEqual(resp.get("status"), "ok", f"Send message failed: {resp}")
        self.assertIn("Message stored for delivery", resp.get("content", ""),
                      "Unexpected message response")
        self.assertIsNotNone(client.session_id, "Client did not store session_id")
        print(f"Successfully sent message from {test_username} to {test_recipient}")

    def test_login_nonexistent_user(self):
        """
        Test that logging in with a username that isn’t registered returns an error.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)
        # Generate a random username that presumably doesn't exist.
        nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))

        # Attempt to login.
        resp = client.send_request(
            action="login",
            from_user=nonexistent_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp.get("status"), "error",
                         "Login should fail with nonexistent username")
        print(f"Successfully prevented login from nonexistent user: {nonexistent_username}")

    def test_register_same_username(self):
        """
        Test that attempting to register the same username twice fails on the second attempt.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)
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

        # Wait briefly to allow the server to process.
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
        print("Successfully prevented duplicate registration of the same username.")

    def test_login_incorrect_password(self):
        """
        Test that logging in with the correct username but an incorrect password fails.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        correct_password = "correctpass"
        wrong_password = "wrongpass"

        # Register the user.
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=correct_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Registration failed for {test_username}: {resp}")

        # Attempt to login with the wrong password.
        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=wrong_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "error",
                         "Login should fail with an incorrect password")
        print(f"Successfully prevented login with an incorrect password.")

if __name__ == "__main__":
    unittest.main()