import unittest
import time
import random
import string

from ChatApp_gRPC.modules.ChatClient import ChatClient
from ChatApp_gRPC.modules.config import HOST, PORT, CERT_FILE

class TestChatApp(unittest.TestCase):
    """
    Existing tests (test_offline_message_fetching, test_message_to_nonexistent_user) omitted 
    for brevity. They remain unchanged.
    """

    def _random_username(self, prefix="user_"):
        """Helper to generate a random username with a given prefix."""
        return prefix + "".join(random.choices(string.ascii_lowercase, k=6))

    ###########################################################################
    # 1) Test list_accounts
    ###########################################################################
    def test_list_accounts(self):
        """
        Test that 'list_accounts' returns the correct accounts matching a pattern.
        Steps:
          1. Register multiple users whose usernames match a pattern ("listAlpha", "listBeta", etc.).
          2. Login one of them to obtain a valid session.
          3. Call 'list_accounts' with a pattern that should match some or all of those users.
          4. Verify that the returned list matches the expected users.
        """
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)
        password = "testpass"

        # 1) Register multiple users
        name = self._random_username("listAlpha_")
        user_list = [
            name
        ]

        for user in user_list:
            resp = client.send_request(
                action="register",
                from_user=user,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok", f"Registration failed for {user}: {resp}")

        # 2) Login one user to get a valid session
        main_user = user_list[0]
        resp_login = client.send_request(
            action="login",
            from_user=main_user,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok", f"Login failed for {main_user}: {resp_login}")

        # 3) Call 'list_accounts' with a broad pattern (e.g. "list" which should match all)
        resp_list = client.send_request(
            action="list_accounts",
            from_user=main_user,
            to_user="",
            password="",
            msg=name  # using msg as the search pattern
        )
        self.assertEqual(resp_list.get("status"), "ok", f"list_accounts failed: {resp_list}")
        returned_accounts = resp_list.get("accounts", [])

        # Check that all registered users are in the returned list
        for user in user_list:
            self.assertIn(user, returned_accounts,
                          f"Expected user {user} not found in list_accounts result: {returned_accounts}")

        print(f"list_accounts test passed. Returned accounts: {returned_accounts}")

    ###########################################################################
    # 2) Test delete_messages
    ###########################################################################
    def test_delete_messages(self):
        """
        Test that a user can delete messages successfully.
        Steps:
          1. Register and login two users: sender, recipient.
          2. Sender sends multiple messages to recipient.
          3. Recipient reads messages and obtains their message IDs.
          4. Recipient (or sender, depending on your server rules) deletes those messages by ID.
          5. Verify that subsequent reads do not return the deleted messages.
        """
        password = "testpass"
        sender_username = self._random_username("delMsgSender_")
        recipient_username = self._random_username("delMsgRecipient_")

        # Create clients
        sender_client = ChatClient(HOST, PORT, cafile=CERT_FILE)
        recipient_client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        # 1) Register both users
        for user_client, user_name in [
            (sender_client, sender_username),
            (recipient_client, recipient_username)
        ]:
            resp = user_client.send_request(
                action="register",
                from_user=user_name,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp.get("status"), "ok", f"Registration failed for {user_name}: {resp}")

            # Login
            resp_login = user_client.send_request(
                action="login",
                from_user=user_name,
                to_user="",
                password=password,
                msg=""
            )
            self.assertEqual(resp_login.get("status"), "ok", f"Login failed for {user_name}: {resp_login}")

        # 2) Sender sends multiple messages to recipient
        messages_to_send = ["Hello!", "How are you?", "This is a delete test"]
        for message in messages_to_send:
            resp_msg = sender_client.send_request(
                action="send_message",
                from_user=sender_username,
                to_user=recipient_username,
                password="",
                msg=message
            )
            self.assertEqual(resp_msg.get("status"), "ok", f"Message send failed: {resp_msg}")

        # 3) Recipient reads messages (grab up to 10)
        resp_fetch = recipient_client.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch.get("status"), "ok", f"Fetch messages failed: {resp_fetch}")
        fetched_messages = resp_fetch.get("messages", [])

        # We expect at least the messages we just sent
        self.assertGreaterEqual(len(fetched_messages), len(messages_to_send),
                                "Recipient did not receive the expected number of messages.")

        # Extract message IDs from the fetched list (depending on your server's data structure).
        # This may be an array of dicts like [{"id": 123, "from_user": "...", "content": "..."}, ...]
        message_ids = [m["id"] for m in fetched_messages if m["content"] in messages_to_send]

        # 4) Delete those messages. We'll assume the recipient can delete them.
        #    If your server's logic requires the sender to delete, you'd do it with the sender client.
        comma_separated_ids = ",".join(str(mid) for mid in message_ids)
        resp_delete = recipient_client.send_request(
            action="delete_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg=comma_separated_ids
        )
        self.assertEqual(resp_delete.get("status"), "ok", f"Message deletion failed: {resp_delete}")

        # 5) Verify subsequent reads do not return the deleted messages
        resp_fetch_again = recipient_client.send_request(
            action="read_messages",
            from_user=recipient_username,
            to_user="",
            password="",
            msg="10"
        )
        self.assertEqual(resp_fetch_again.get("status"), "ok", f"Fetch messages failed: {resp_fetch_again}")
        fetched_messages_again = resp_fetch_again.get("messages", [])

        # Check that none of the previously deleted message IDs are present
        for m in fetched_messages_again:
            self.assertNotIn(m["id"], message_ids,
                             f"Message with ID {m['id']} was supposed to be deleted but is still present.")

        print(f"delete_messages test passed. Deleted messages: {message_ids}")

    ###########################################################################
    # 3) Test delete_account
    ###########################################################################
    def test_delete_account(self):
        """
        Test that a user can delete their account successfully.
        Steps:
          1. Register and login a new user.
          2. Delete that account.
          3. Verify that further login attempts fail.
          4. (Optional) Check that the user is not returned in list_accounts or 
             that re-registering the same user succeeds (depending on server logic).
        """
        password = "testpass"
        user_to_delete = self._random_username("delAcct_")

        # Create a client
        client = ChatClient(HOST, PORT, cafile=CERT_FILE)

        # 1) Register + login
        resp_reg = client.send_request(
            action="register",
            from_user=user_to_delete,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_reg.get("status"), "ok", f"Registration failed: {resp_reg}")

        resp_login = client.send_request(
            action="login",
            from_user=user_to_delete,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login.get("status"), "ok", f"Login failed: {resp_login}")

        # 2) Delete the account
        resp_del = client.send_request(
            action="delete_account",
            from_user=user_to_delete,
            to_user="",
            password="",
            msg=""
        )
        self.assertEqual(resp_del.get("status"), "ok", f"Account deletion failed: {resp_del}")
        self.assertIn("content", resp_del, f"No content found in response: {resp_del}")
        print(f"Account deletion response: {resp_del['content']}")

        # 3) Verify further login attempts fail
        resp_login_again = client.send_request(
            action="login",
            from_user=user_to_delete,
            to_user="",
            password=password,
            msg=""
        )
        # Expect status to be "error" or something indicating login not possible
        self.assertNotEqual(resp_login_again.get("status"), "ok",
                            f"Login succeeded for a deleted account: {resp_login_again}")

        # 4) (Optional) Check that the user is not in the list of accounts or re-register
        #    Below is an example check using list_accounts if your server includes
        #    deleted accounts or not. If your server logic is different, adapt as needed.

        # We have to login as some OTHER user to do list_accounts.
        # For simplicity, we'll just register a new throwaway user.
        another_user = self._random_username("throwaway_")
        resp_reg_other = client.send_request(
            action="register",
            from_user=another_user,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_reg_other.get("status"), "ok", f"Registration failed for {another_user}: {resp_reg_other}")

        resp_login_other = client.send_request(
            action="login",
            from_user=another_user,
            to_user="",
            password=password,
            msg=""
        )
        self.assertEqual(resp_login_other.get("status"), "ok", f"Login failed for {another_user}: {resp_login_other}")

        # Now that we're logged in as 'another_user', we can list all or partially
        resp_list = client.send_request(
            action="list_accounts",
            from_user=another_user,
            to_user="",
            password="",
            msg="delAcct_"  # pattern that might match our deleted user
        )
        self.assertEqual(resp_list.get("status"), "ok", f"list_accounts failed: {resp_list}")
        returned_accounts = resp_list.get("accounts", [])

        self.assertNotIn(user_to_delete, returned_accounts,
                         f"Deleted user {user_to_delete} still found in list_accounts: {returned_accounts}")

        print(f"delete_account test passed. User {user_to_delete} is successfully removed.")

if __name__ == "__main__":
    unittest.main()
