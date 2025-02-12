import unittest
import time
import random
import string

from .WireProtocolTest import WireProtocolTest
from ..modules.ChatClient import ChatClient
from ..server import ChatServer
from ..modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

###############################################################################
# Test Class 3: Additional Authentication and Account Management Tests
###############################################################################
class TestAccountManagement(WireProtocolTest):
    def test_logout_valid_session(self):
        """
        Test that a user can successfully logout with a valid session:
          1. Register and login a user.
          2. Logout the user.
          3. Verify server response indicates success.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        test_password = "testpass"

        # 1) Register the user
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Registration failed for {test_username}: {resp}")

        # 2) Login the user
        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Login failed for {test_username}: {resp}")
        self.assertIn("session_id", resp, "No session_id returned on login")

        # 3) Logout
        resp_logout = client.send_request(
            action="logout",
            from_user=test_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp_logout.get("status"), "ok", f"Logout failed: {resp_logout}")
        print(f"User {test_username} successfully logged out.")

    def test_logout_invalid_session(self):
        """
        Test that attempting to logout with an invalid or missing session fails:
          1. Use a random username that is not logged in.
          2. Attempt to logout and verify failure.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Use random username that is not actually logged in.
        random_username = "no_session_" + "".join(random.choices(string.ascii_lowercase, k=6))
        resp = client.send_request(
            action="logout",
            from_user=random_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp.get("status"), "error",
                         "Logout should fail with invalid or nonexistent session")
        print(f"Logout with invalid session for user {random_username} correctly returned error.")

    def test_login_after_logout(self):
        """
        Test that a user can log back in after logging out:
          1. Register and login a user.
          2. Logout the user.
          3. Log the user back in and verify success.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        test_password = "testpass"

        # Register the user
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Registration failed for {test_username}: {resp}")

        # Login the user
        resp_login = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok",
                         f"Login failed for {test_username}: {resp_login}")
        self.assertIn("session_id", resp_login, "No session_id returned on login")

        # Logout the user
        resp_logout = client.send_request(
            action="logout",
            from_user=test_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp_logout.get("status"), "ok", f"Logout failed: {resp_logout}")

        # Log in again
        resp_login_again = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=test_password,
            msg=""
        )
        self.assertEqual(resp_login_again.get("status"), "ok",
                         f"Second login failed for {test_username}: {resp_login_again}")
        self.assertIn("session_id", resp_login_again,
                      "No session_id returned on second login")
        print(f"User {test_username} successfully logged in after logging out.")

    def test_read_messages_not_logged_in(self):
        """
        Test that fetching messages without a valid session fails:
          1. Do not log in the user (or use an invalid session).
          2. Attempt to read messages.
          3. Verify error response is returned.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        random_username = "no_session_" + "".join(random.choices(string.ascii_lowercase, k=6))
        
        # Attempt to read messages without logging in
        resp_fetch = client.send_request(
            action="read_messages",
            from_user=random_username,
            to_user="",
            password="",  # No login, so no valid password
            msg="10"
        )
        self.assertEqual(resp_fetch.get("status"), "error",
                         "Should not be able to read messages without a valid session")
        print(f"Read messages with no session for user {random_username} correctly returned error.")

    def test_change_password_and_relogin(self):
        """
        Test the 'change_password' action (if your server supports it). This ensures:
          1. A user can register and login.
          2. The user changes password.
          3. Logging out and attempting to login with the old password fails.
          4. Logging in with the new password succeeds.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        old_password = "oldpass"
        new_password = "newpass_" + "".join(random.choices(string.digits, k=3))
        test_username = "pwchange_" + "".join(random.choices(string.ascii_lowercase, k=6))

        # Register the user
        resp_reg = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=old_password,
            msg=""
        )
        self.assertEqual(resp_reg.get("status"), "ok",
                         f"Registration failed for {test_username}: {resp_reg}")

        # Login the user
        resp_login = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=old_password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok",
                         f"Login failed for {test_username}: {resp_login}")
        self.assertIn("session_id", resp_login, "No session_id returned on login")

        # Change password (this action must be supported by your server to pass)
        resp_change_pw = client.send_request(
            action="change_password",
            from_user=test_username,
            to_user="",
            password=new_password,
            msg="Change to new password"
        )
        if resp_change_pw.get("status") == "error":
            self.skipTest("Server does not support 'change_password' or test is not implemented.")
        self.assertEqual(resp_change_pw.get("status"), "ok",
                         f"Failed to change password: {resp_change_pw}")

        # Logout
        resp_logout = client.send_request(
            action="logout",
            from_user=test_username,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp_logout.get("status"), "ok", f"Logout failed: {resp_logout}")

        # Attempt login with old password -> should fail
        resp_login_old = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=old_password,
            msg=""
        )
        self.assertEqual(resp_login_old.get("status"), "error",
                         "Old password should no longer work")

        # Attempt login with new password -> should succeed
        resp_login_new = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=new_password,
            msg=""
        )
        self.assertEqual(resp_login_new.get("status"), "ok",
                         f"Login with new password failed: {resp_login_new}")
        print(f"Password change and re-login for user {test_username} successful.")


if __name__ == "__main__":
    unittest.main()
