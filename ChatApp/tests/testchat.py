# test_chat.py
import unittest
import random
import string

from transport import send_json_request  # The helper from step 1

def random_string(length=8):
    """Generate a random alphanumeric string."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

class TestChatServer(unittest.TestCase):

    def test_register_login_message(self):
        """
        1) Register a random user with a random password
        2) Login with the same credentials
        3) Send a message to 'alice' with the text 'yo'
        4) Assert responses from the server are as expected
        """

        username = f"test_{random_string()}"
        password = f"pwd_{random_string()}"

        # 1) Register
        register_req = {
            "action": "register",
            "from": username,
            "password": password,
            "to": "",
            "message": "",
            "session_id": None,
        }
        register_resp = send_json_request(register_req)
        self.assertEqual(register_resp["status"], "ok", msg=f"Register failed: {register_resp}")

        # 2) Login
        login_req = {
            "action": "login",
            "from": username,
            "password": password,
            "to": "",
            "message": "",
            "session_id": None,
        }
        login_resp = send_json_request(login_req)
        self.assertEqual(login_resp["status"], "ok", msg=f"Login failed: {login_resp}")
        self.assertIn("session_id", login_resp, "No session_id returned on login")

        session_id = login_resp["session_id"]

        # 3) Send a message
        message_req = {
            "action": "message",
            "from": username,
            "password": "",
            "to": "alice",
            "message": "yo",
            "session_id": session_id,
        }
        message_resp = send_json_request(message_req)
        self.assertEqual(
            message_resp["status"], "ok",
            msg=f"Message action failed: {message_resp}"
        )
        self.assertIn(
            "Message delivered to alice",
            message_resp.get("message", ""),
            "Server did not confirm message delivery to alice"
        )

if __name__ == "__main__":
    unittest.main()