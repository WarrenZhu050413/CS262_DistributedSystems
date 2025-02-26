import unittest
import time
import random
import string

from ChatApp_gRPC.modules.ChatClient import ChatClient
from ChatApp_gRPC.modules.config import HOST, PORT, CERT_FILE

###############################################################################
# Test Class 2: Message
###############################################################################
class TestChatApp(unittest.TestCase):

    def test_message_fetching(self):
        """
        Test that messages delivered to a recipient are stored and can be fetched 
        when the recipient logs back on.
        Steps:
          1. Register and login a sender.
          2. Register a recipient but do not start its persistent listener.
          3. Sender sends a message to the recipient.
          4. Recipient logs in later and fetches messages.
          5. Verify that the fetched messages contain the sent message.
        """
        client_sender = ChatClient(HOST, PORT, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, PORT, cafile=CERT_FILE)

        sender_username = "sender_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        test_message = "Message test"

        # 1) Register both users.
        for user in [sender_username, recipient_username]:
            resp = client_sender.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok",
                             f"Registration failed for {user}: {resp}")

        # 2) Login sender.
        resp_sender = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender.get("status"), "ok", f"Login failed for sender: {resp_sender}")
        self.assertIn("session_id", resp_sender, "No session_id returned on sender login")

        # Register the recipient as well, but we won't start its listener until later.
        resp_recipient = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient.get("status"), "ok", f"Login failed for recipient: {resp_recipient}")
        self.assertIn("session_id", resp_recipient, "No session_id returned on recipient login")

        # 3) Sender sends a message.
        resp_msg = client_sender.send_request(
            action="send_message",
            from_user=sender_username,
            to_user=recipient_username,
            password="",
            msg=test_message
        )
        self.assertEqual(resp_msg.get("status"), "ok", f"Message send failed: {resp_msg}")

        # 4) Simulate time passing; then recipient "comes online" with a new client instance.
        time.sleep(0.5)

        client_recipient_new = ChatClient(HOST, PORT, cafile=CERT_FILE)
        resp_recipient_new = client_recipient_new.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient_new.get("status"), "ok",
                         f"Recipient re-login failed: {resp_recipient_new}")

        # 5) Fetch messages (we'll fetch up to 10).
        resp_fetch = client_recipient_new.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch.get("status"), "ok", f"Fetch messages failed: {resp_fetch}")
        messages = resp_fetch.get("messages", [])
        found = any(test_message in m.get("content", "") for m in messages)
        self.assertTrue(found, "Fetched messages did not include the message.")
        print(f"Message fetching successful for {recipient_username}")

    def test_message_to_nonexistent_user(self):
        """
        Test that a user cannot send a message to a nonexistent user.
        Steps:
          1. Register and login a sender.
          2. Generate a random username that does not exist.
          3. Attempt to send a message to that username.
          4. Verify that the response status is error.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # 1) Register + login the sender.
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Registration failed for {test_username}: {resp}")

        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", f"Login failed for {test_username}: {resp}")

        # 2) Generate a random nonexistent username (no extra checks).
        nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))

        # 3) Attempt to send a message to that username.
        resp = client.send_request(
            action="send_message",
            from_user=test_username,
            to_user=nonexistent_username,
            password="",
            msg="Test message to nonexistent user"
        )

        # 4) Verify that the server responds with an error.
        self.assertEqual(resp.get("status"), "error",
                         "Message should not be sent to a nonexistent user.")
        print(f"Successfully prevented messaging to nonexistent user: {nonexistent_username}")

if __name__ == "__main__":
    unittest.main()