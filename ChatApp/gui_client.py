#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A minimal Tkinter GUI client to send a message to the echo server and display the response
"""

import tkinter as tk
import socket

HOST = "127.0.0.1"
PORT = 54400

def send_message():
    """Connect to server, send the text from input_box, and display response."""
    user_msg = input_box.get()
    if not user_msg:
        response_label.config(text="Please enter a message!")
        return
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(user_msg.encode('utf-8'))
            
            data = s.recv(1024)
            server_response = data.decode('utf-8')
            
            response_label.config(text=f"Server responded: {server_response}")
    except ConnectionRefusedError:
        response_label.config(text="Could not connect to server. Is it running?")
    except Exception as e:
        response_label.config(text=f"Error: {str(e)}")

# Create the main application window
root = tk.Tk()
root.title("Simple Socket Client")

# Label for instructions
instruction_label = tk.Label(root, text="Enter a message to send to the server:")
instruction_label.pack(pady=5)

# Text entry for the message
input_box = tk.Entry(root, width=50)
input_box.pack(pady=5)

# Button to trigger send
send_btn = tk.Button(root, text="Send", command=send_message)
send_btn.pack(pady=5)

# Label to display the server's response
response_label = tk.Label(root, text="", fg="blue")
response_label.pack(pady=10)

# Start the GUI event loop
root.mainloop()
