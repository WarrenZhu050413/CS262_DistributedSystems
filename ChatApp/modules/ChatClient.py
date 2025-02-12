import socket
import ssl
import threading  # REAL-TIME MOD: Needed for the listener thread
from typing import Dict, Any, Optional
from .WireMessageBinary import WireMessageBinary

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

        # NEW: Attributes to manage the persistent listener.
        self.listener_thread = None
        self.listener_socket = None

    def send_request(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        """
        Build the request, send it over the socket, receive the response.
        Return the parsed response.
        """
        wire_message: bytes = WireMessageBinary.make_wire_message(
            action=action,
            from_user=from_user,
            to_user=to_user,
            password=password,
            msg=msg,
            session_id=self.session_id
        )

        # Open the socket and wrap it in SSL.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect((self.host, self.port))
            with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
                # Send the wire message.
                s.sendall(wire_message)

                # Read the response.
                resp_bytes: bytes = WireMessageBinary.read_wire_message(s)
                resp_dict: Dict[str, Any] = WireMessageBinary.parse_wire_message(resp_bytes)

                # Store the session_id if provided by the server.
                if "session_id" in resp_dict:
                    self.session_id = resp_dict["session_id"]
                return resp_dict
            
    def delete_account(self, username):
        wire_message = WireMessageBinary.make_wire_message(
            action="delete_account",
            from_user=username,
            to_user="",  # not used for deletion
            password="",  # not needed here
            msg="",
            session_id=self.session_id
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect((self.host, self.port))
            with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
                s.sendall(wire_message)
                resp_bytes: bytes = WireMessageBinary.read_wire_message(s)
                resp_dict: Dict[str, Any] = WireMessageBinary.parse_wire_message(resp_bytes)
                return resp_dict

    # ------------------------------
    # NEW: Persistent listener for real-time messages
    # ------------------------------
    def start_listener(self, from_user: str, callback) -> None:
        """
        Establish a persistent connection to the server and send a 'listen' request.
        Then, in a background thread, continuously read pushed messages and invoke the callback.
        """
        def listen_thread():
            s = None
            try:
                # Create and connect the raw socket.
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_socket.connect((self.host, self.port))
                # Wrap the raw socket in SSL.
                s = self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host)
                # Save the socket so it can be closed later.
                self.listener_socket = s

                # Build and send the listen request.
                listen_wire_message: bytes = WireMessageBinary.make_wire_message(
                    action="listen",
                    from_user=from_user,
                    to_user="",
                    password="",
                    msg="",
                    session_id=self.session_id
                )
                s.sendall(listen_wire_message)
                try:
                    # Read the server's acknowledgement.
                    resp_bytes: bytes = WireMessageBinary.read_wire_message(s)
                except Exception as e:
                    return  # Exit if reading acknowledgement fails

                # Now keep reading pushed messages indefinitely.
                while True:
                    try:
                        msg_bytes = WireMessageBinary.read_wire_message(s)
                    except Exception as e:
                        break  # Exit loop if an error occurs (or if the socket is closed)
                    msg_dict = WireMessageBinary.parse_wire_message(msg_bytes)
                    callback(msg_dict)
            except Exception as e:
                callback({"status": "error", "error": str(e)})
            finally:
                if s is not None:
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    s.close()
                    self.listener_socket = None
        self.listener_thread = threading.Thread(target=listen_thread, daemon=True)
        self.listener_thread.start()

    def stop_listener(self):
        if self.listener_socket is not None:
            self.listener_socket.close()
            self.listener_socket = None

