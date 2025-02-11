import socket
import json
import ssl
from typing import Dict, Any, Optional

class ChatClient:
    def __init__(self, host: str, port: int, cafile: str) -> None:
        self.host: str = host
        self.port: int = port
        self.session_id: Optional[str] = None  # Keep session state here if needed

        # Create and configure the SSL context
        self.context: ssl.SSLContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(cafile=cafile)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def build_message(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        """
        Build a JSON dictionary with the specified parameters.
        Returns a Python dictionary.
        
        'action' can be "register", "login", "message", "list_accounts", or "read_messages".
        'msg' is reused for various purposes (e.g. the text pattern for list_accounts,
        the number of messages to fetch for read_messages, etc.).
        """
        return {
            "action": action,
            "from": from_user,
            "to": to_user,
            "password": password,
            "message": msg,
            "session_id": self.session_id,
        }

    def send_request(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        """
        Build the request, send it over the socket, receive the response.
        Return the parsed JSON response.

        Example usage for listing accounts:
            send_request("list_accounts", my_user, "", "", "A%")

        Example usage for reading messages (fetch 5 messages):
            send_request("read_messages", my_user, "", "", "5")
        """
        request_obj: Dict[str, Any] = self.build_message(action, from_user, to_user, password, msg)
        wire_message: str = json.dumps(request_obj)
        msg_bytes: bytes = wire_message.encode('utf-8')
        prefix: bytes = len(msg_bytes).to_bytes(4, 'big')

        # Open the socket and wrap it in SSL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect((self.host, self.port))
            with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
                # Send length + JSON payload
                s.sendall(prefix + msg_bytes)

                # Read the response length prefix (4 bytes)
                length_data: bytes = self._recv_exactly(s, 4)
                if not length_data:
                    raise ConnectionError("No response length received from server.")

                resp_length: int = int.from_bytes(length_data, 'big')
                # Read exactly resp_length bytes for the JSON response
                resp_data: bytes = self._recv_exactly(s, resp_length)
                if not resp_data:
                    raise ConnectionError("Server closed connection before sending a full response.")

                # Parse and handle JSON
                resp_json: Dict[str, Any] = json.loads(resp_data.decode('utf-8'))

                # Store the session_id if provided by the server
                if "session_id" in resp_json:
                    self.session_id = resp_json["session_id"]
                return resp_json

    def _recv_exactly(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Read exactly n bytes from the socket.
        Returns the bytes or None if the connection closes prematurely.
        """
        buf: bytes = b""
        while len(buf) < n:
            chunk: bytes = sock.recv(n - len(buf))
            if not chunk:
                return None  # Connection closed
            buf += chunk
        return buf