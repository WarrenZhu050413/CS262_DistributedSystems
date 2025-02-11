import socket
import json
import ssl
import threading  # REAL-TIME MOD: Needed for the listener thread
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
        
        'action' can be "register", "login", "message", "list_accounts", "read_messages", or "listen".
        'msg' is reused for various purposes.
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

    # ------------------------------
    # NEW: Persistent listener for real-time messages
    # ------------------------------
    def start_listener(self, from_user: str, callback) -> None:
        """
        Establish a persistent connection to the server and send a 'listen' request.
        Then, in a background thread, continuously read pushed messages and invoke the callback.
        """
        def listen_thread():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
                    raw_socket.connect((self.host, self.port))
                    with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
                        # Build and send the listen request
                        listen_req = self.build_message("listen", from_user, "", "", "")
                        wire_message = json.dumps(listen_req)
                        msg_bytes = wire_message.encode('utf-8')
                        prefix = len(msg_bytes).to_bytes(4, 'big')
                        s.sendall(prefix + msg_bytes)
                        # Optionally, read the server's acknowledgement
                        length_data = self._recv_exactly(s, 4)
                        if not length_data:
                            return
                        resp_length = int.from_bytes(length_data, 'big')
                        _ = self._recv_exactly(s, resp_length)  # discard or log acknowledgement

                        # Now keep reading pushed messages indefinitely
                        while True:
                            length_data = self._recv_exactly(s, 4)
                            if not length_data:
                                break
                            msg_length = int.from_bytes(length_data, 'big')
                            msg_data = self._recv_exactly(s, msg_length)
                            if not msg_data:
                                break
                            msg_json = json.loads(msg_data.decode('utf-8'))
                            callback(msg_json)
            except Exception as e:
                # Optionally, pass the error to the callback
                callback({"status": "error", "error": str(e)})

        t = threading.Thread(target=listen_thread, daemon=True)
        t.start()
