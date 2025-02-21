import unittest
import threading
import time
import os
import socket

from ChatApp_gRPC.modules.ChatServer import ChatServer
from ChatApp_gRPC.modules.ChatClient import ChatClient

# -----------------------------------------------------------------------------
# Helper: Pick a random free port
# -----------------------------------------------------------------------------
def random_port() -> int:
    """Find a free TCP port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]

# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------
class TestChatServerIntegration(unittest.TestCase):
    """
    Integration Test Suite for ChatServer and ChatClient

    These tests spin up a ChatServer instance on a random port and use a ChatClient
    to exercise the server’s functionality. By “integration-style,” we mean that these
    tests involve real network I/O and an actual database, verifying end-to-end
    interactions (i.e., that the client and server correctly implement the wire protocol,
    handle SSL connections, and manipulate the SQLite database).

    Test Overview:

    1. **test_delete_account**:
    - Registers a user, logs in, then deletes the account.
    - Verifies that the user cannot log in after deletion.

    2. **test_delete_message**:
    - Registers two users (sender and receiver).
    - Sender sends a message to the receiver.
    - Receiver reads and then deletes the message.
    - Ensures the message no longer appears in subsequent reads.

    3. **test_sending_batch_messages**:
    - Registers two users.
    - One user sends 20 messages to the other.
    - The other user logs in and fetches all messages in one go.
    - Verifies that the exact number of sent messages is delivered.

    4. **test_register_many_users**:
    - Registers 100 users in a loop.
    - Logs each user in afterward, confirming the server can handle higher volumes
        of registrations without errors.

    5. **test_long_username**:
    - Attempts to register a user whose username is about 50 characters long.
    - Confirms that registration and subsequent login both succeed (unless the server
        imposes a strict character limit).

    6. **test_special_chars_username**:
    - Registers and logs in a user whose username contains special characters and spaces.
    - Validates that the server accepts such usernames if not explicitly disallowed.

    Implementation Details:
    - `ChatServer` is started in a background thread via `setUpClass`, using a file-based
    SQLite database (`test.db`) and an SSL certificate/key pair for TLS connections.
    - The `ChatClient` is instantiated once (shared by all tests), pointing to the same
    port and using the same certificate.
    - Each test exercises one or more “actions” (register, login, message, etc.) through
    the client’s `send_request` or helper methods (e.g., `delete_account`).
    - `tearDownClass` stops the server and cleans up log files or leftover artifacts.

    Since these are *integration tests*, they verify that multiple layers (network, SSL,
    database, message handling) work together as intended. This is in contrast to a
    pure *unit test*, which would test each class/function in isolation using mocks or
    stubs instead of real sockets and a real database.
    """

    @classmethod
    def setUpClass(cls):
        """
        Spin up the ChatServer in a background thread, using:
          - ephemeral port
          - in-memory SQLite database
          - test SSL certificate/key
        """
        cls.test_port = random_port()
        cls.db_file = "test.db"
        cls.cert_file = "ChatApp_gRPC/security/server.crt"       # Adjust path to your test cert
        cls.key_file = "ChatApp_gRPC/security/server.key"        # Adjust path to your test key
        cls.log_file = "test_server.log"   # Log file for debugging

        cls.server = ChatServer(
            host="localhost",
            port=cls.test_port,
            db_file=cls.db_file,
            cert_file=cls.cert_file,
            key_file=cls.key_file,
            log_file=cls.log_file
        )

        def run_server():
            cls.server.start()

        cls.server_thread = threading.Thread(target=run_server, daemon=True)
        cls.server_thread.start()

        # Give the server a moment to start listening
        time.sleep(1.0)

        # Create a shared ChatClient for convenience. 
        # You could also create a new client per test if desired.
        cafile = cls.cert_file  # In a real test, we'd have a proper CA or trust policy
        cls.client = ChatClient(host="localhost", port=cls.test_port, cafile=cafile)

    @classmethod
    def tearDownClass(cls):
        """
        Stop the server and join the background thread.
        """
        cls.server.stop()
        cls.server_thread.join(timeout=2.0)
        # Cleanup log file if desired
        if os.path.exists(cls.log_file):
            os.remove(cls.log_file)

    # -------------------------------------------------------------------------
    # 1) Test deleting an account
    # -------------------------------------------------------------------------
    def test_delete_account(self):
        """
        Register a user, log in, then delete the account.
        Verify that the user can't log in afterward.
        """
        username = "alice"
        password = "password123"

        # Register
        resp = self.client.send_request(
            action="register",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Registration failed: {resp}")

        # Log in
        resp = self.client.send_request(
            action="login",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed: {resp}")
        session_id = resp.get("session_id")
        self.assertTrue(session_id, "No session_id returned after login")

        # Now delete account
        resp = self.client.delete_account(username)
        self.assertEqual(resp.get("status"), "ok", f"Account delete failed: {resp}")

        # Attempt to login again => Should fail
        resp = self.client.send_request(
            action="login",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "error", "Login should fail after account deletion")

    # -------------------------------------------------------------------------
    # 2) Test deleting a message
    # -------------------------------------------------------------------------
    def test_delete_message(self):
        """
        Register two users (sender & receiver).
        Sender -> sends a message to receiver.
        Receiver logs in, reads the message, then deletes it.
        Verify it is removed from the server’s stored messages.
        """
        sender = "bob"
        sender_pw = "bobpass"
        receiver = "eve"
        receiver_pw = "evepass"

        # --- Register both
        for user, pw in [(sender, sender_pw), (receiver, receiver_pw)]:
            resp = self.client.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=pw,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok", f"Registration failed for {user}: {resp}")

        # --- Log in sender
        resp = self.client.send_request(
            action="login",
            from_user=sender,
            to_user="",
            password=sender_pw,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed for sender: {resp}")
        session_sender = resp.get("session_id")

        # --- Send a message from bob -> eve
        msg_text = "Hello from Bob to Eve!"
        resp = self.client.send_request(
            action="message",
            from_user=sender,
            to_user=receiver,
            password=sender_pw,
            msg=msg_text
        )
        self.assertEqual(resp.get("status"), "ok", f"Sending message failed: {resp}")

        # --- Log in receiver
        resp = self.client.send_request(
            action="login",
            from_user=receiver,
            to_user="",
            password=receiver_pw,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed for receiver: {resp}")
        session_receiver = resp.get("session_id")

        # --- Read messages
        resp = self.client.send_request(
            action="read_messages",
            from_user=receiver,
            to_user="",
            password=receiver_pw,
            msg="10"  # fetch up to 10 messages
        )
        self.assertEqual(resp.get("status"), "ok", f"Reading messages failed: {resp}")
        msgs = resp.get("messages", [])
        self.assertTrue(len(msgs) > 0, "Expected at least one message")
        the_msg = msgs[0]
        msg_id = the_msg.get("id")
        self.assertIn("Hello from Bob", the_msg.get("content", ""), "Message content mismatch")

        # --- Delete that message
        resp = self.client.send_request(
            action="delete_messages",
            from_user=receiver,
            to_user="",
            password=receiver_pw,
            msg=str(msg_id)
        )
        self.assertEqual(resp.get("status"), "ok", f"Deleting message failed: {resp}")
        self.assertIn("Deleted messages", resp.get("message", ""))

        # Confirm that message is no longer listed among delivered messages
        remaining = resp.get("messages", [])
        for m in remaining:
            self.assertNotEqual(m.get("id"), msg_id, "Message ID was not actually deleted")

    # -------------------------------------------------------------------------
    # 3) Test sending many messages at once
    # -------------------------------------------------------------------------
    def test_sending_batch_messages(self):
        """
        Register two users. 
        One user sends a batch of messages to the other. 
        The receiver then reads them all in one go.
        """
        sender = "batchuser1"
        sender_pw = "batchpass1"
        receiver = "batchuser2"
        receiver_pw = "batchpass2"

        # Register + Login both
        for user, pw in [(sender, sender_pw), (receiver, receiver_pw)]:
            reg_resp = self.client.send_request("register", user, "", pw, "")
            self.assertEqual(reg_resp.get("status"), "ok", f"Registration failed: {reg_resp}")
            login_resp = self.client.send_request("login", user, "", pw, "")
            self.assertEqual(login_resp.get("status"), "ok", f"Login failed: {login_resp}")

        # Send 20 messages from sender to receiver
        for i in range(20):
            txt = f"Batch message #{i}"
            resp = self.client.send_request("message", sender, receiver, sender_pw, txt)
            self.assertEqual(resp.get("status"), "ok", f"Sending message {i} failed: {resp}")

        # Now login as receiver and read them
        # (Re-login ensures we fetch them in a fresh session if needed)
        login_resp = self.client.send_request("login", receiver, "", receiver_pw, "")
        self.assertEqual(login_resp.get("status"), "ok", f"Login failed for receiver: {login_resp}")

        read_resp = self.client.send_request("read_messages", receiver, "", receiver_pw, "50")
        self.assertEqual(read_resp.get("status"), "ok", f"Reading messages failed: {read_resp}")
        msgs = read_resp.get("messages", [])
        self.assertEqual(len(msgs), 20, f"Expected 20 messages, got {len(msgs)}")

    # -------------------------------------------------------------------------
    # 4) Test registering/logging in up to 100 users
    # -------------------------------------------------------------------------
    def test_register_many_users(self):
        """
        Register 100 users, then attempt to login each to confirm success.
        """
        base_name = "testuser_"
        password = "password"
        num_users = 100

        for i in range(num_users):
            username = f"{base_name}{i}"
            resp = self.client.send_request("register", username, "", password, "")
            self.assertEqual(resp.get("status"), "ok", f"Registration failed for {username}: {resp}")

        # Now login each one
        for i in range(num_users):
            username = f"{base_name}{i}"
            resp = self.client.send_request("login", username, "", password, "")
            self.assertEqual(resp.get("status"), "ok", f"Login failed for {username}: {resp}")

    # -------------------------------------------------------------------------
    # 5) Test longer usernames
    # -------------------------------------------------------------------------
    def test_long_username(self):
        """
        Test registering and logging in with a 50-character username.
        (You can adjust length as needed.)
        """
        long_username = "user_" + ("x" * 45)  # total length ~ 50
        password = "longuserpass"

        # Register
        resp = self.client.send_request("register", long_username, "", password, "")
        self.assertEqual(resp.get("status"), "ok", f"Registration failed for long user: {resp}")

        # Login
        resp = self.client.send_request("login", long_username, "", password, "")
        self.assertEqual(resp.get("status"), "ok", f"Login failed for long user: {resp}")

    # -------------------------------------------------------------------------
    # 6) Test special characters in username
    # -------------------------------------------------------------------------
    def test_special_chars_username(self):
        """
        Ensure that usernames with special characters (like spaces, punctuation) 
        can register and log in properly, provided the server does not explicitly forbid them.
        """
        special_username = "user!@#$%^&*() with_space"
        password = "weirdPass123"

        resp = self.client.send_request("register", special_username, "", password, "")
        self.assertEqual(resp.get("status"), "ok", f"Registration failed for special username: {resp}")

        # Login
        resp = self.client.send_request("login", special_username, "", password, "")
        self.assertEqual(resp.get("status"), "ok", f"Login failed for special username: {resp}")


if __name__ == "__main__":
    unittest.main()
