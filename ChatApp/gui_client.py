#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A minimal Tkinter GUI client to send a length-prefixed JSON message to the server
and display the JSON response.
"""

import tkinter as tk
import socket
import json
import ssl
from config import HOST, PORT

def send_message():
    """Connect to server, send a JSON message (with length prefix), and display the JSON response."""
    user_msg = input_box.get().strip()
    if not user_msg:
        response_label.config(text="Please enter a JSON message!")
        return

    try:
        # Convert the input text to bytes
        msg_bytes = user_msg.encode('utf-8')

        # Calculate the 4-byte length prefix (big-endian)
        prefix = len(msg_bytes).to_bytes(4, 'big')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect((HOST, PORT))
            with context.wrap_socket(raw_socket, server_side=False, server_hostname=HOST) as s:
                # Send length + JSON payload
                s.sendall(prefix + msg_bytes)

                # Now read the response length prefix (4 bytes)
                length_data = recv_exactly(s, 4)
                if not length_data:
                    response_label.config(text="No response length received from server.")
                    return

                resp_length = int.from_bytes(length_data, 'big')
                # Read exactly resp_length bytes for the JSON response
                resp_data = recv_exactly(s, resp_length)
                if not resp_data:
                    response_label.config(text="Server closed connection before sending full response.")
                    return

                # Decode and parse JSON
                try:
                    resp_json = json.loads(resp_data.decode('utf-8'))
                    response_label.config(text=f"Server responded with JSON:\n{resp_json}")
                except json.JSONDecodeError as e:
                    response_label.config(text=f"Error decoding JSON response: {e}")

    except ConnectionRefusedError:
        response_label.config(text="Could not connect to server. Is it running?")
    except Exception as e:
        response_label.config(text=f"Error: {str(e)}")

def recv_exactly(sock, n):
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

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile="server.crt")
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Create the main application window
root = tk.Tk()
root.title("Length-Prefixed JSON Client")

# Label for instructions
instruction_label = tk.Label(root, text="Enter a JSON string to send to the server:")
instruction_label.pack(pady=5)

# Text entry for the message
input_box = tk.Entry(root, width=80)
input_box.pack(pady=5)

# Button to trigger send
send_btn = tk.Button(root, text="Send JSON", command=send_message)
send_btn.pack(pady=5)

# Label to display the server's response
response_label = tk.Label(root, text="", fg="blue", justify="left")
response_label.pack(pady=10)

# Start the GUI event loop
root.mainloop()
