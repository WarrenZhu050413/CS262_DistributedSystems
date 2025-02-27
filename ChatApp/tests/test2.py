import unittest
import threading
import time
import os
import random
import string
import socket

from .WireProtocolTest import WireProtocolTest
from ..modules.ChatClient import ChatClient
from ..server import ChatServer
from ..modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

###############################################################################
# Test Class 2: Message
###############################################################################
class TestChatApp(WireProtocolTest):
    """
    Test suite for the Chat Application's messaging functionality.

    This test class verifies the following key features:

    test_real_time_message_delivery:
        - Tests real-time message delivery between two online users
        - Verifies that messages are delivered immediately when both users are online
        - Checks that the recipient's listener callback receives messages
        - Ensures proper cleanup of SSL sockets

    test_offline_message_fetching:
        - Tests message delivery to offline users
        - Verifies messages are stored when recipient is offline
        - Ensures stored messages can be retrieved when recipient logs back in
        - Tests the read_messages functionality

    test_message_to_nonexistent_user:
        - Tests error handling when sending to invalid users
        - Verifies messages cannot be sent to nonexistent usernames
        - Ensures proper error responses from the server
    """

    def test_real_time_message_delivery(self):
        """
        Test that real-time message delivery works for two online users.
        Steps:
          1. Register and login two users (sender and recipient).
          2. Start a persistent listener for the recipient.
          3. Sender sends a message to the recipient.
          4. Verify that the recipient's listener callback receives the message in real time.
        """
        # Create separate clients for sender and recipient.
        client_sender = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        # Generate random usernames and password.
        sender_username = "sender_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        test_message = "Real-time message test"

        # Register both users.
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

        # Login both users.
        resp_sender = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender.get("status"), "ok", f"Login failed for sender: {resp_sender}")
        self.assertIn("session_id", resp_sender, "No session_id returned on sender login")

        resp_recipient = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient.get("status"), "ok", f"Login failed for recipient: {resp_recipient}")
        self.assertIn("session_id", resp_recipient, "No session_id returned on recipient login")

        # Set up a list to capture real-time delivered messages.
        delivered_messages = []

        def listener_callback(msg_json):
            # Append the message if status is ok.
            delivered_messages.append(msg_json)

        # Start the persistent listener for the recipient.
        client_recipient.start_listener(recipient_username, listener_callback)
        time.sleep(0.5)  # Allow time for the listener thread to start

        # Sender sends a message to the recipient.
        resp_msg = client_sender.send_request(
            action="message",
            from_user=sender_username,
            to_user=recipient_username,
            password="",
            msg=test_message
        )
        self.assertEqual(resp_msg.get("status"), "ok", f"Message send failed: {resp_msg}")

        # Wait for real-time delivery.
        time.sleep(1.0)
        # Verify that the listener received the message.
        self.assertTrue(len(delivered_messages) > 0, "Real-time listener did not receive any messages")
        found = any(test_message in msg.get("message", "") for msg in delivered_messages if msg.get("status") == "ok")
        self.assertTrue(found, "Real-time listener did not receive the expected message")
        print(f"Real-time message delivery successful from {sender_username} to {recipient_username}")

        # NEW: Stop the listener to close the SSL socket and avoid ResourceWarning.
        client_recipient.stop_listener()

    def test_offline_message_fetching(self):
        """
        Test that messages delivered to an offline recipient are stored and can be fetched 
        when the recipient logs back on.
        Steps:
          1. Register and login a sender.
          2. Register a recipient but do not start its persistent listener (simulate offline).
          3. Sender sends multiple messages to the recipient.
          4. Recipient logs in later and fetches messages.
          5. Verify that the fetched messages contain all sent messages.
        """
        client_sender = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        sender_username = "sender_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        test_messages = [f"Offline message test #{i}" for i in range(15)]

        # Register both users.
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

        # Login sender.
        resp_sender = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender.get("status"), "ok", f"Login failed for sender: {resp_sender}")
        self.assertIn("session_id", resp_sender, "No session_id returned on sender login")

        # Login recipient but do not start listener.
        resp_recipient = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient.get("status"), "ok", f"Login failed for recipient: {resp_recipient}")
        self.assertIn("session_id", resp_recipient, "No session_id returned on recipient login")

        # Sender sends multiple messages.
        sent_messages = []
        for test_message in test_messages:
            resp_msg = client_sender.send_request(
                action="message",
                from_user=sender_username,
                to_user=recipient_username,
                password="",
                msg=test_message
            )
            self.assertEqual(resp_msg.get("status"), "ok", f"Message send failed: {resp_msg}")
            sent_messages.append(test_message)
            time.sleep(0.1)  # Small delay between messages

        # Allow time for all messages to be stored.
        time.sleep(0.5)

        # Simulate recipient coming online (new client instance) and fetch messages.
        client_recipient_new = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        resp_recipient_new = client_recipient_new.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient_new.get("status"), "ok", f"Recipient re-login failed: {resp_recipient_new}")
        
        # Fetch messages.
        resp_fetch = client_recipient_new.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg="15"  # Request all 15 messages
        )
        self.assertEqual(resp_fetch.get("status"), "ok", f"Fetch messages failed: {resp_fetch}")
        messages = resp_fetch.get("messages", [])
        
        # Verify all sent messages were received
        received_messages = [m.get("content", "") for m in messages]
        for sent_msg in sent_messages:
            self.assertIn(sent_msg, received_messages, f"Message '{sent_msg}' not found in fetched messages")
        
        # Verify the count of messages
        self.assertEqual(len(messages), len(sent_messages), 
                        f"Expected {len(sent_messages)} messages, but got {len(messages)}")
        
        print(f"Successfully fetched {len(messages)} offline messages for {recipient_username}")

    def test_message_to_nonexistent_user(self):
        """
        Test that a user cannot send a message to a nonexistent user.
        Steps:
          1. Register and login a sender.
          2. Generate a random username that does not exist.
          3. Attempt to send a message to that username.
          4. Verify that the response status is error.
        """
        client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        # Register and login the sender.
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
        # Generate a random nonexistent username.
        nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))
        # Ensure it doesn't exist.
        while nonexistent_username in self.server.get_all_usernames():
            nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))
        # Attempt to send a message.
        resp = client.send_request(
            action="message",
            from_user=test_username,
            to_user=nonexistent_username,
            password="",
            msg="Test message to nonexistent user"
        )
        self.assertEqual(resp.get("status"), "error",
                         "Message should not be sent to a nonexistent user")
        print(f"Successfully prevented messaging to nonexistent user: {nonexistent_username}")

if __name__ == "__main__":
    unittest.main()
