import unittest
import time
import random
import string

from ChatApp_gRPC.modules.ChatClient import ChatClient
from ChatApp_gRPC.modules.config import HOST, PORT, CERT_FILE
from ChatApp_gRPC.proto_generated.chat_pb2 import PushObject


class TestChatApp(unittest.TestCase):

    def test_message_fetching(self):
        """
        Test that messages delivered to a recipient are stored and can be fetched 
        when the recipient logs back on.
        """
        client_sender = ChatClient(HOST, PORT, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, PORT, cafile=CERT_FILE)

        sender_username = "sender_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        test_message = "Message test"

        # 1) Register both users
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

        # 2) Login sender
        resp_sender = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender.get("status"), "ok", 
                         f"Login failed for sender: {resp_sender}")

        # 3) Sender sends a message (recipient is not listening yet)
        resp_msg = client_sender.send_request(
            action="send_message",
            from_user=sender_username,
            to_user=recipient_username,
            password="",
            msg=test_message
        )
        self.assertEqual(resp_msg.get("status"), "ok", 
                         f"Message send failed: {resp_msg}")

        # 4) Recipient logs in later
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

        # 5) Fetch messages
        resp_fetch = client_recipient_new.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch.get("status"), "ok", 
                         f"Fetch messages failed: {resp_fetch}")
        messages = resp_fetch.get("messages", [])
        found = any(test_message in m.get("content", "") for m in messages)
        self.assertTrue(found, "Fetched messages did not include the sent message.")

        # More descriptive success message:
        print(
            f"[TEST PASSED: test_message_fetching] "
            f"Sender '{sender_username}' successfully sent offline message to '{recipient_username}', "
            f"which was fetched later."
        )

    def test_message_to_nonexistent_user(self):
        """
        Test that a user cannot send a message to a nonexistent user.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)
        test_username = "testuser_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # 1) Register & Login
        resp = client.send_request(
            action="register",
            from_user=test_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", 
                         f"Registration failed for {test_username}: {resp}")

        resp = client.send_request(
            action="login",
            from_user=test_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp.get("status"), "ok", 
                         f"Login failed for {test_username}: {resp}")

        # 2) Attempt to send to a nonexistent username
        nonexistent_username = "nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=6))
        resp_send = client.send_request(
            action="send_message",
            from_user=test_username,
            to_user=nonexistent_username,
            password="",
            msg="Test message to nonexistent user"
        )

        # 3) Verify that the server responds with an error
        self.assertEqual(resp_send.get("status"), "error",
                         "Message should not be sent to a nonexistent user.")

        print(
            f"[TEST PASSED: test_message_to_nonexistent_user] "
            f"Server correctly rejected message to nonexistent user '{nonexistent_username}'."
        )

    def test_real_time_messaging(self):
        """
        Test that a message is received in real-time if the recipient 
        has started a persistent listener.
        """
        client_sender = ChatClient(HOST, PORT, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, PORT, cafile=CERT_FILE)

        sender_username = "sender_rt_" + "".join(random.choices(string.ascii_lowercase, k=6))
        recipient_username = "recipient_rt_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"
        test_message = "Hello from real-time test"

        # 1) Register both
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

        # 2) Login both
        resp_sender_login = client_sender.send_request(
            action="login",
            from_user=sender_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_sender_login.get("status"), "ok", 
                         "Sender login failed")

        resp_recipient_login = client_recipient.send_request(
            action="login",
            from_user=recipient_username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_recipient_login.get("status"), "ok", 
                         "Recipient login failed")
        session_id_recipient = resp_recipient_login["session_id"]

        # 3) Start recipient's listener
        received_msgs = []

        def on_message_callback(push_obj: PushObject):
            received_msgs.append((push_obj.from_user, push_obj.content))

        client_recipient.start_listener(
            username=recipient_username,
            session_id=session_id_recipient,
            callback=on_message_callback
        )
        time.sleep(0.5)  # ensure listener is active

        # 4) Sender sends a message
        resp_send = client_sender.send_request(
            action="send_message",
            from_user=sender_username,
            to_user=recipient_username,
            password="",
            msg=test_message
        )
        self.assertEqual(resp_send.get("status"), "ok", 
                         f"Real-time send_message failed: {resp_send}")

        # 5) Wait for real-time delivery
        time.sleep(1.5)
        found = any(msg == test_message for _, msg in received_msgs)
        self.assertTrue(found, "Real-time message not received by callback")

        print(
            f"[TEST PASSED: test_real_time_messaging] "
            f"Real-time message '{test_message}' was successfully delivered to '{recipient_username}'."
        )

    def test_delete_messages(self):
        """
        Test deleting messages from the server and verify they no longer appear.
        """
        client_sender = ChatClient(HOST, PORT, cafile=CERT_FILE)
        client_recipient = ChatClient(HOST, PORT, cafile=CERT_FILE)

        userA = "userA_" + "".join(random.choices(string.ascii_lowercase, k=6))
        userB = "userB_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # 1) Register & login both
        for user in [userA, userB]:
            resp = client_sender.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok", 
                             f"Registration failed for {user}: {resp}")

        respA_login = client_sender.send_request(
            action="login",
            from_user=userA,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(respA_login.get("status"), "ok", 
                         "User A login failed")

        respB_login = client_recipient.send_request(
            action="login",
            from_user=userB,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(respB_login.get("status"), "ok", 
                         "User B login failed")

        # 2) A sends multiple messages to B
        message_texts = ["msg1", "msg2", "msg3"]
        for txt in message_texts:
            resp_send = client_sender.send_request(
                action="send_message",
                from_user=userA,
                to_user=userB,
                password="",
                msg=txt
            )
            self.assertEqual(resp_send.get("status"), "ok", 
                             f"send_message to B failed: {resp_send}")

        # 3) B fetches all
        resp_fetch = client_recipient.send_request(
            action="read_messages",
            from_user=userB,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch.get("status"), "ok", 
                         f"B read messages failed: {resp_fetch}")
        messages = resp_fetch.get("messages", [])
        self.assertEqual(len(messages), 3, "B should have exactly 3 messages")

        # 4) Delete 2 of them
        ids_to_delete = [m["id"] for m in messages[:2]]
        delete_str = ",".join(map(str, ids_to_delete))
        resp_delete = client_recipient.send_request(
            action="delete_messages",
            from_user=userB,
            to_user="",
            password="",
            msg=delete_str
        )
        self.assertEqual(resp_delete.get("status"), "ok", 
                         f"Delete messages failed: {resp_delete}")

        # 5) Fetch again -> Those IDs should not appear
        resp_fetch2 = client_recipient.send_request(
            action="read_messages",
            from_user=userB,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch2.get("status"), "ok", 
                         f"Second fetch messages failed: {resp_fetch2}")
        messages_after_delete = resp_fetch2.get("messages", [])

        for m in messages_after_delete:
            self.assertNotIn(m["id"], ids_to_delete, 
                             "Found a deleted message in the new fetch")

        print(
            f"[TEST PASSED: test_delete_messages] "
            f"Messages with IDs {ids_to_delete} were successfully deleted for '{userB}'."
        )

    def test_delete_account(self):
        """
        Test deleting an account. The user should not be able to log in afterward.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        username = "delacct_" + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # 1) Register + login
        resp_reg = client.send_request(
            action="register",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_reg.get("status"), "ok", 
                         f"Registration failed: {resp_reg}")

        resp_login = client.send_request(
            action="login",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok", 
                         f"Login failed: {resp_login}")

        # 2) Delete the account
        resp_delete = client.send_request(
            action="delete_account",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_delete.get("status"), "ok", 
                         f"Delete account failed: {resp_delete}")

        # 3) Attempt to log in again -> should fail
        resp_login_again = client.send_request(
            action="login",
            from_user=username,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login_again.get("status"), "error", 
                         "Login should fail after account deletion.")

        print(
            f"[TEST PASSED: test_delete_account] "
            f"User '{username}' was deleted and can no longer log in."
        )

    def test_list_accounts(self):
        """
        Test listing user accounts with a wildcard pattern.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        prefix = "listtest_"
        user1 = prefix + "".join(random.choices(string.ascii_lowercase, k=6))
        user2 = prefix + "".join(random.choices(string.ascii_lowercase, k=6))
        password = "testpass"

        # 1) Register both
        for u in [user1, user2]:
            resp = client.send_request(
                action="register",
                from_user=u,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok", 
                             f"Registration failed for {u}: {resp}")

        # 2) Login user1
        resp_login = client.send_request(
            action="login",
            from_user=user1,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok", 
                         "Login failed for user1")

        # 3) List accounts with a wildcard pattern
        wildcard_pattern = prefix + "*"
        resp_list = client.send_request(
            action="list_accounts",
            from_user=user1,
            to_user="",
            password="",
            msg=wildcard_pattern
        )
        self.assertEqual(resp_list.get("status"), "ok", 
                         f"List accounts failed: {resp_list}")
        accounts = resp_list.get("accounts", [])

        # Ensure both user1 and user2 are in the returned list
        self.assertIn(user1, accounts, 
                      "User1 not found in list_accounts response")
        self.assertIn(user2, accounts, 
                      "User2 not found in list_accounts response")

        print(
            f"[TEST PASSED: test_list_accounts] "
            f"Wildcard pattern '{wildcard_pattern}' successfully listed '{user1}' and '{user2}'."
        )


if __name__ == "__main__":
    unittest.main()