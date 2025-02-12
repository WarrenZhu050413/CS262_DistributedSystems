import unittest
import threading
import time
import random
import string

from .WireProtocolTest import WireProtocolTest
from ..modules.ChatClient import ChatClient
from ..server import ChatServer
from ..modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

###############################################################################
# Test Class 4: Concurrency and Stress Tests
###############################################################################
class TestConcurrency(WireProtocolTest):

    def test_simultaneous_registration(self):
        """
        Test that the server can handle simultaneous registration requests for different users.
        Steps:
          1. Spin up multiple threads trying to register different random users.
          2. Each registration should succeed independently.
        """
        number_of_threads = 5
        registered_users = []
        errors = []

        def register_user(thread_id):
            client = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
            username = f"user_{thread_id}_" + "".join(random.choices(string.ascii_lowercase, k=6))
            resp = client.send_request(
                action="register",
                from_user=username,
                to_user="",
                password="testpass",
                msg=""
            )
            if resp.get("status") == "ok":
                registered_users.append(username)
            else:
                errors.append((username, resp))

        threads = []
        for i in range(number_of_threads):
            t = threading.Thread(target=register_user, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0,
            f"Some registrations failed under concurrency: {errors}")
        self.assertEqual(len(registered_users), number_of_threads,
            "Not all threads were able to register users successfully")
        print(f"Simultaneous registrations succeeded for {number_of_threads} users.")

    def test_multiple_senders_one_recipient(self):
        """
        Test that multiple senders can concurrently send messages to one recipient.
        Steps:
          1. Register and login a single recipient.
          2. Spawn several sender threads, each registering, logging in, and sending a message.
          3. Verify the recipient eventually receives all messages (when reading).
        """
        # 1) Set up the recipient
        client_recipient = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # Register the recipient
        resp = client_recipient.send_request(
            action="register",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Registration failed for recipient: {resp}")

        # Login the recipient
        resp = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok",
                         f"Login failed for recipient: {resp}")
        self.assertIn("session_id", resp, "No session_id returned on recipient login")

        # 2) Spawn multiple sender threads
        number_of_senders = 5
        messages_sent = []
        errors = []

        def send_message(sender_id):
            client_sender = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
            sender_username = f"sender_{sender_id}_" + "".join(random.choices(string.ascii_lowercase, k=6))
            # Register sender
            resp_reg = client_sender.send_request(
                action="register",
                from_user=sender_username,
                to_user="",
                password=password,
                msg=""
            )
            if resp_reg.get("status") != "ok":
                errors.append((sender_username, "registration", resp_reg))
                return

            # Login sender
            resp_login = client_sender.send_request(
                action="login",
                from_user=sender_username,
                to_user="",
                password=password,
                msg=""
            )
            if resp_login.get("status") != "ok":
                errors.append((sender_username, "login", resp_login))
                return

            # Send message
            test_message = f"Hello from {sender_username}"
            resp_msg = client_sender.send_request(
                action="message",
                from_user=sender_username,
                to_user=recipient_username,
                password="",
                msg=test_message
            )
            if resp_msg.get("status") == "ok":
                messages_sent.append(test_message)
            else:
                errors.append((sender_username, "message", resp_msg))

        threads = []
        for i in range(number_of_senders):
            t = threading.Thread(target=send_message, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0,
                         f"Some senders encountered errors: {errors}")
        # Wait a moment for the server to process
        time.sleep(1.0)

        # 3) Verify the recipient sees all messages
        resp_fetch = client_recipient.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg=str(number_of_senders * 2)  # fetch enough to get all messages
        )
        self.assertEqual(resp_fetch.get("status"), "ok",
                         f"Failed to read messages: {resp_fetch}")
        received = resp_fetch.get("messages", [])
        # Count how many of our messages are in the retrieved list
        found_count = sum(
            any(sent_msg in m.get("content", "") for m in received) for sent_msg in messages_sent
        )
        self.assertEqual(found_count, number_of_senders,
                         f"Recipient did not receive all messages; found {found_count} of {number_of_senders}")
        print(f"Multiple senders successfully sent messages to {recipient_username}.")

    def test_stress_message_sending(self):
        """
        Test sending a large number of messages from a single sender to a single recipient 
        to ensure the server/database can handle it.
        Steps:
          1. Register/login sender and recipient.
          2. Send N messages in a loop.
          3. Read them from the recipient's side to verify all are stored.
        """
        client_sender = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, self.__class__.port, cafile=CERT_FILE)

        sender_username = "sender_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        N = 20  # Number of messages to send

        # 1) Register and login for both
        for user in [sender_username, recipient_username]:
            resp_reg = client_sender.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_reg.get("status"), "ok",
                             f"Registration failed for {user}: {resp_reg}")

        resp_sender_login = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender_login.get("status"), "ok",
                         f"Sender login failed: {resp_sender_login}")
        resp_recipient_login = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient_login.get("status"), "ok",
                         f"Recipient login failed: {resp_recipient_login}")

        # 2) Send N messages
        sent_messages = []
        for i in range(N):
            test_message = f"Stress test message {i}"
            resp_msg = client_sender.send_request(
                action="message",
                from_user=sender_username,
                to_user=recipient_username,
                password="",
                msg=test_message
            )
            self.assertEqual(resp_msg.get("status"), "ok", f"Message send failed: {resp_msg}")
            sent_messages.append(test_message)

        # Give the server a moment to store messages
        time.sleep(1.0)

        # 3) Read messages from recipient
        resp_fetch = client_recipient.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg=str(N + 10)  # fetch enough to cover all messages
        )
        self.assertEqual(resp_fetch.get("status"), "ok", f"Fetch messages failed: {resp_fetch}")
        received = resp_fetch.get("messages", [])
        # Check we have the expected messages
        found_count = sum(
            any(m.get("content") == sent_msg for m in received)
            for sent_msg in sent_messages
        )
        self.assertEqual(found_count, N, f"Expected {N} messages, found {found_count}")
        print(f"Stress message sending test successful with {N} messages from {sender_username} to {recipient_username}.")


if __name__ == "__main__":
    unittest.main()
