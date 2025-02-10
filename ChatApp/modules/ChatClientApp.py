import tkinter as tk
from typing import Dict, Any, Optional
from .config import HOST, PORT
from .ChatClient import ChatClient

class ChatClientApp:
    def __init__(self, root: tk.Tk, client: ChatClient) -> None:
        """
        Initialize the GUI and keep a reference to the ChatClient instance.
        """
        self.root = root
        self.client = client  # The new ChatClient instance
        self.root.title("Length-Prefixed JSON Client")

        # For convenience, use StringVars to hold input field values
        self.action_var: tk.StringVar = tk.StringVar()
        self.from_var: tk.StringVar = tk.StringVar()
        self.to_var: tk.StringVar = tk.StringVar()
        self.password_var: tk.StringVar = tk.StringVar()
        self.message_var: tk.StringVar = tk.StringVar()

        # Build the GUI
        self.build_gui()

    def build_gui(self) -> None:
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
        send_btn = tk.Button(self.root, text="Send Request", command=self.on_send_click)
        send_btn.pack(pady=5)

        # Label to display the server's response
        self.response_label: tk.Label = tk.Label(self.root, text="", fg="blue", justify="left")
        self.response_label.pack(pady=10)

    def on_send_click(self) -> None:
        """
        Retrieve values from the GUI, call the ChatClient to send the request,
        and display the response.
        """
        action: str = self.action_var.get().strip()
        from_user: str = self.from_var.get().strip()
        to_user: str = self.to_var.get().strip()
        msg: str = self.message_var.get().strip()
        password: str = self.password_var.get().strip()

        # Basic validation
        if not action:
            self.response_label.config(text="Please specify an action (e.g., login/register/message).")
            return

        try:
            resp_json: Dict[str, Any] = self.client.send_request(action, from_user, to_user, password, msg)
            self.response_label.config(text=f"Server responded with JSON:\n{resp_json}")
        except ConnectionRefusedError:
            self.response_label.config(text="Could not connect to server. Is it running?")
        except Exception as e:
            self.response_label.config(text=f"Error: {str(e)}")