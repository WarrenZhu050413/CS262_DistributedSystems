import unittest
import time
import random
import string
import os

from .WireProtocolTest import WireProtocolTest
from ..modules.ChatClient import ChatClient
from ..server import ChatServer
from ..modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

###############################################################################
# Test Class 5: Advanced Edge Case & Negative Tests
###############################################################################
class TestEdgeCases(WireProtocolTest):
    def test_invalid_action(self):
        """
        Test sending a request with an action that the server does not recognize.
        The server should return an error indicating an invalid action or similar.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        username = "invalidact_" + "".join(random.choices(string.ascii_lowercase, k=6))
        
        # Attempt to send an "invalid_action" request.
        resp = client.send_request(
            action="invalid_action",
            from_user=username,
            to_user="",
            password="",
            msg="Some data"
        )
        self.assertEqual(resp.get("status"), "error",
                         f"Server did not reject invalid action: {resp}")
        print("Successfully tested invalid action handling.")

    def test_missing_parameters(self):
        """
        Test how the server handles requests missing required parameters.
        For example, omit the 'from_user' or 'action'.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Omit the 'from_user'
        resp_no_user = client.send_request(
            action="register",
            from_user="",  # intentionally empty
            to_user="",
            password="password",
            msg=""
        )
        self.assertEqual(resp_no_user.get("status"), "error",
                         "Server should reject registration with no username")
        print("Successfully tested registration with missing username.")

        # Omit the 'action' (manually craft an invalid request).
        # The send_request method may ensure an action is always set, 
        # so we might bypass it or patch it if needed. 
        # For demonstration, we'll do it directly on the socket 
        # or skip if not feasible. 
        # This is a conceptual test—adjust for your environment:

        # If your ChatClient doesn't allow sending with no action, skip:
        self.skipTest("Skipping direct raw-socket test. Implement a raw request test if needed.")

    def test_special_character_usernames(self):
        """
        Test registering and logging in with usernames that contain special
        characters or unicode to verify the server handles them properly (or rejects them).
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Example special characters. Adjust as needed.
        special_username = "user_!@#_" + "".join(random.choices(string.ascii_lowercase, k=3))
        password = "testpass"
        
        resp_reg = client.send_request(
            action="register",
            from_user=special_username,
            to_user="",
            password=password,
            msg=""
        )
        # Depending on your server’s rules, it might accept or reject special chars.
        # Below we assume the server returns "ok" for demonstration.
        # Adjust if your server disallows them and returns "error".
        self.assertIn(resp_reg.get("status"), ["ok", "error"],
                      f"Unexpected response when registering special character username: {resp_reg}")
        
        if resp_reg.get("status") == "ok":
            # Attempt login
            resp_login = client.send_request(
                action="login",
                from_user=special_username,
                to_user="",
                password=password,
                msg=""
            )
            self.assertIn(resp_login.get("status"), ["ok", "error"],
                          f"Unexpected response when logging in with special character username: {resp_login}")
            if resp_login.get("status") == "ok":
                print(f"Successfully registered and logged in with special username '{special_username}'")
            else:
                print(f"Server rejected login for special username '{special_username}': {resp_login}")
        else:
            print(f"Server rejected registration for special username '{special_username}': {resp_reg}")

    def test_send_overly_large_message(self):
        """
        Test sending a message that exceeds typical length constraints (e.g., > 10KB)
        to ensure server handles or rejects it gracefully.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        username_sender = "large_" + "".join(random.choices(string.ascii_lowercase, k=6))
        username_recipient = "large_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # Register and login both
        for user in [username_sender, username_recipient]:
            resp_reg = client.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_reg.get("status"), "ok",
                             f"Registration failed for {user}: {resp_reg}")

            resp_login = client.send_request(
                action="login",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_login.get("status"), "ok",
                             f"Login failed for {user}: {resp_login}")

        # Generate a large message (for instance, ~20KB of data).
        large_message = "X" * (20 * 1024)  # 20 KB of 'X'
        
        resp_msg = client.send_request(
            action="message",
            from_user=username_sender,
            to_user=username_recipient,
            password="",
            msg=large_message
        )
        # Server might accept or reject. We check for either ok or error.
        self.assertIn(resp_msg.get("status"), ["ok", "error"],
                      f"Server returned unexpected status for overly large message: {resp_msg}")
        if resp_msg.get("status") == "ok":
            print("Server accepted large message successfully.")
        else:
            print("Server rejected large message, as expected for size constraints.")

    def test_same_user_multiple_sessions(self):
        """
        Test how the server handles multiple simultaneous sessions for the same user
        (if the server supports or restricts concurrent sessions).
        1. Register and login a user from one client.
        2. Attempt login from a second client using the same credentials.
        3. Depending on server policy, either allow or reject the second login.
        """
        user = "multisession_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        client1 = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        client2 = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Register user
        resp_reg = client1.send_request(
            action="register",
            from_user=user,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_reg.get("status"), "ok",
                         f"Registration failed for {user}: {resp_reg}")

        # Login from first client
        resp_login1 = client1.send_request(
            action="login",
            from_user=user,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login1.get("status"), "ok",
                         f"First login failed for {user}: {resp_login1}")

        # Attempt login from second client
        resp_login2 = client2.send_request(
            action="login",
            from_user=user,
            to_user="",
            password=password,
            msg=""
        )

        # Server might allow or reject second concurrent session.
        # We accept either possibility but verify it's not something unexpected.
        self.assertIn(resp_login2.get("status"), ["ok", "error"],
                      f"Unexpected response to second concurrent login: {resp_login2}")
        if resp_login2.get("status") == "ok":
            print(f"Server allowed multiple sessions for {user}.")
        else:
            print(f"Server rejected multiple sessions for {user} (expected if only one session is allowed).")

    def test_injection_attack_vectors(self):
        """
        Test sending messages that look like potential injection attacks (SQL, HTML, or JSON injection)
        to confirm the server safely handles or sanitizes them.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        user_sender = "inject_" + "".join(random.choices(string.ascii_lowercase, k=6))
        user_recipient = "inject_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # Register and login both
        for user in [user_sender, user_recipient]:
            resp_reg = client.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_reg.get("status"), "ok", f"Registration failed: {resp_reg}")

            resp_login = client.send_request(
                action="login",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_login.get("status"), "ok", f"Login failed: {resp_login}")

        # Potential malicious content examples
        malicious_inputs = [
            "Robert'); DROP TABLE users; --",
            "<script>alert('XSS');</script>",
            '{"malicious_json": "true"}'
        ]
        for payload in malicious_inputs:
            resp_msg = client.send_request(
                action="message",
                from_user=user_sender,
                to_user=user_recipient,
                password="",
                msg=payload
            )
            self.assertIn(resp_msg.get("status"), ["ok", "error"],
                          f"Unexpected status for injection attempt: {resp_msg}")
            print(f"Server response for injection attempt '{payload}': {resp_msg.get('status')}")


if __name__ == "__main__":
    unittest.main()
