#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A minimal Tkinter GUI client to send a length-prefixed JSON message to the server
and display the JSON response, refactored into a class-based approach.
"""

import tkinter as tk
import socket
import json
import ssl
from config import HOST, PORT


class ChatClientApp:
    def __init__(self, root):
        """
        Initialize the GUI, SSL context, and instance variables.
        """
        self.root = root
        self.root.title("Length-Prefixed JSON Client")

        # Session ID (if needed after login/register)
        self.session_id = None

        # Create and configure the SSL context
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(cafile="./security/server.crt")
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        # For convenience, use StringVars to hold input field values
        self.action_var = tk.StringVar()
        self.from_var = tk.StringVar()
        self.to_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.message_var = tk.StringVar()

        # Build the GUI
        self.build_gui()

    def build_gui(self):
        """
        Create and pack all GUI elements: labels, text entries, and buttons.
        """
        tk.Label(self.root, text="Action (login/register/message):").pack(pady=2, anchor='w')
        tk.Entry(self.root, textvariable=self.action_var, width=50).pack(pady=2)

        tk.Label(self.root, text="From (username):").pack(pady=2, anchor='w')
        tk.Entry(self.root, textvariable=self.from_var, width=50).pack(pady=2)

        tk.Label(self.root, text="To (recipient username):").pack(pady=2, anchor='w')
        tk.Entry(self.root, textvariable=self.to_var, width=50).pack(pady=2)

        tk.Label(self.root, text="Password (for register/login):").pack(pady=2, anchor='w')
        tk.Entry(self.root, textvariable=self.password_var, show='*', width=50).pack(pady=2)

        tk.Label(self.root, text="Message (for 'message' action):").pack(pady=2, anchor='w')
        tk.Entry(self.root, textvariable=self.message_var, width=50).pack(pady=2)

        # Button to trigger send
        send_btn = tk.Button(self.root, text="Send Request", command=self.send_message)
        send_btn.pack(pady=5)

        # Label to display the server's response
        self.response_label = tk.Label(self.root, text="", fg="blue", justify="left")
        self.response_label.pack(pady=10)

    def build_message(self, action, from_user, to_user, password, msg):
        """
        Construct the JSON request string based on user inputs and session_id.
        """
        # If no action is provided, update the response_label and return None
        if not action:
            self.response_label.config(
                text="Please specify an action (e.g., login, register, message)."
            )
            return None

        # Build the request as a dict
        request_obj = {
            "action": action,
            "from": from_user,
            "to": to_user,
            "password": password,
            "message": msg,
            "session_id": self.session_id,
        }

        # Convert to a JSON string
        return json.dumps(request_obj)

    def recv_exactly(self, sock, n):
        """
        Helper to read exactly n bytes from the socket.
        Returns the bytes or None if the connection closes prematurely.
        """
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None  # Connection closed
            buf += chunk
        return buf

    def send_message(self):
        """
        Connect to server, send a JSON message (with length prefix), and display the JSON response.
        """
        action = self.action_var.get().strip()
        from_user = self.from_var.get().strip()
        to_user = self.to_var.get().strip()
        msg = self.message_var.get().strip()
        password = self.password_var.get().strip()  # for register/login

        wire_message = self.build_message(
            action=action,
            from_user=from_user,
            to_user=to_user,
            password=password,
            msg=msg,
        )
        if wire_message is None:
            # build_message() already updated the response label
            return

        msg_bytes = wire_message.encode('utf-8')
        prefix = len(msg_bytes).to_bytes(4, 'big')

        # Attempt connection and data exchange
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
                raw_socket.connect((HOST, PORT))
                with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=HOST) as s:
                    # Send length + JSON payload
                    s.sendall(prefix + msg_bytes)

                    # Now read the response length prefix (4 bytes)
                    length_data = self.recv_exactly(s, 4)
                    if not length_data:
                        self.response_label.config(text="No response length received from server.")
                        return

                    resp_length = int.from_bytes(length_data, 'big')
                    # Read exactly resp_length bytes for the JSON response
                    resp_data = self.recv_exactly(s, resp_length)
                    if not resp_data:
                        self.response_label.config(
                            text="Server closed connection before sending full response."
                        )
                        return

                    # Decode and parse JSON
                    try:
                        resp_json = json.loads(resp_data.decode('utf-8'))
                        self.response_label.config(text=f"Server responded with JSON:\n{resp_json}")

                        # If the server returned a session_id, store it
                        if "session_id" in resp_json:
                            self.session_id = resp_json["session_id"]
                    except json.JSONDecodeError as e:
                        self.response_label.config(text=f"Error decoding JSON response: {e}")

        except ConnectionRefusedError:
            self.response_label.config(text="Could not connect to server. Is it running?")
        except Exception as e:
            self.response_label.config(text=f"Error: {str(e)}")


def main():
    """
    Create the root window, instantiate the ChatClientApp, and run the Tk event loop.
    """
    root = tk.Tk()
    app = ChatClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()