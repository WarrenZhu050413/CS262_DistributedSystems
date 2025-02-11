import socket
import json
import ssl
import threading  # REAL-TIME MOD: Needed for the listener thread
from typing import Dict, Any, Optional
from .WireMessageJSON import WireMessageJSON

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

    def _parse_response(self, response: bytes) -> Dict[str, Any]:
        """
        Parse the response from the server.
        """
        return json.loads(response.decode('utf-8'))

    def send_request(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        """
        Build the request, send it over the socket, receive the response.
        Return the parsed JSON response.
        """
        wire_message: bytes = WireMessageJSON.make_wire_message(action=action, from_user=from_user, to_user=to_user, password=password, msg=msg, session_id=self.session_id)

        # Open the socket and wrap it in SSL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect((self.host, self.port))
            with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
                # Send the wire message
                s.sendall(wire_message)

                # Read the response
                resp_bytes: bytes = WireMessageJSON.read_wire_message(s)
                resp_json: Dict[str, Any] = WireMessageJSON.parse_wire_message(resp_bytes)

                # Store the session_id if provided by the server
                if "session_id" in resp_json:
                    self.session_id = resp_json["session_id"]
                return resp_json

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
                        listen_wire_message: bytes = WireMessageJSON.make_wire_message(action="listen", from_user=from_user, to_user="", password="", msg="", session_id=self.session_id)
                        s.sendall(listen_wire_message)
                        try:
                            resp_bytes: bytes = WireMessageJSON.read_wire_message(s)
                        except Exception as e:
                            return

                        # Now keep reading pushed messages indefinitely
                        while True:
                            try:
                                msg_bytes = WireMessageJSON.read_wire_message(s)
                            except Exception as e:
                                break
                            msg_json = WireMessageJSON.parse_wire_message(msg_bytes)
                            callback(msg_json)
            except Exception as e:
                # Optionally, pass the error to the callback
                callback({"status": "error", "error": str(e)})

        t = threading.Thread(target=listen_thread, daemon=True)
        t.start()
