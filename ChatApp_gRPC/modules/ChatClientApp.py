import tkinter as tk
from typing import Dict, Any, Optional
from .config import HOST, PORT
from .ChatClient import ChatClient

class ChatClientApp:
    """
    A GUI application for a chat client using tkinter.
    
    This class implements a complete chat interface with the following features:
    - User authentication (login, register, delete account)
    - Real-time messaging between users
    - Message management (send, receive, delete messages)
    - Account search with wildcard pattern matching
    - Paginated display of search results
    - Message history with fetch and delete capabilities
    
    The GUI is organized into distinct frames for:
    1. Authentication (username/password)
    2. Messaging (send messages to other users)
    3. Account searching (find other users)
    4. Message management (view/delete messages)
    
    The app maintains a persistent connection to the server for real-time
    message updates while providing a responsive user interface.

    How it works:
    Uses tkinter to create a GUI.
    Uses ChatClient to send requests to the server.
    Uses the handle_incoming_message() method to handle real-time messages from the server.
    """

    def __init__(self, root: tk.Tk, client: ChatClient) -> None:
        """
        Initialize the GUI and keep a reference to the ChatClient instance.

        Args:
            root (tk.Tk): The root Tkinter window
            client (ChatClient): Instance of the chat client for server communication
        """
        self.root = root
        self.client = client  # The new ChatClient instance
        self.root.title("Wire Protocol Client")

        # For convenience, use StringVars to hold input field values
        self.action_var: tk.StringVar = tk.StringVar()
        self.from_var: tk.StringVar = tk.StringVar()
        self.to_var: tk.StringVar = tk.StringVar()
        self.password_var: tk.StringVar = tk.StringVar()
        self.message_var: tk.StringVar = tk.StringVar()

        # --- New variables for account searching ---
        self.search_pattern_var: tk.StringVar = tk.StringVar()
        # We will store the full list of search results here once the server returns them
        self.search_results = []
        # Track the current "page" or index range we are displaying
        self.search_results_index = 0
        self.results_per_page = 5  # For example, show 5 at a time

        # --- New variables for reading messages ---
        self.fetch_count_var: tk.StringVar = tk.StringVar(value="5")  # default to 5 messages at a time
        self.incoming_messages_text: Optional[tk.Text] = None

        # Build the GUI
        self.build_gui()

    def build_gui(self) -> None:
        """
        Create and pack all GUI elements: labels, text entries, and buttons.
        Organizes the interface into frames for authentication, messaging, searching, and message management.
        """
        # ========= User Authentication Frame =========
        auth_frame = tk.LabelFrame(self.root, text="User Authentication")
        auth_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Username and Password fields for login/register (using from_var and password_var)
        tk.Label(auth_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        tk.Entry(auth_frame, textvariable=self.from_var, width=30).grid(row=0, column=1, padx=5, pady=5)

        tk.Label(auth_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        tk.Entry(auth_frame, textvariable=self.password_var, show='*', width=30).grid(row=1, column=1, padx=5, pady=5)

        # Buttons for Login and Register actions
        login_btn = tk.Button(auth_frame, text="Login", command=self.on_login_click)
        login_btn.grid(row=2, column=0, padx=5, pady=5, sticky="e")

        register_btn = tk.Button(auth_frame, text="Register", command=self.on_register_click)
        register_btn.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        delete_account_btn = tk.Button(auth_frame, text="Delete Account", command=self.on_delete_account)
        delete_account_btn.grid(row=2, column=2, padx=5, pady=5, sticky="e")

        # ========= Messaging Frame =========
        msg_frame = tk.LabelFrame(self.root, text="Send Message")
        msg_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Recipient field (using to_var)
        tk.Label(msg_frame, text="Recipient:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        tk.Entry(msg_frame, textvariable=self.to_var, width=30).grid(row=0, column=1, padx=5, pady=5)

        # Message field (using message_var) with Send Message button right beside it
        tk.Label(msg_frame, text="Message:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        tk.Entry(msg_frame, textvariable=self.message_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        send_msg_btn = tk.Button(msg_frame, text="Send Message", command=self.on_send_message_click)
        send_msg_btn.grid(row=1, column=2, padx=5, pady=5)

        # Label to display the server's response
        self.response_label: tk.Label = tk.Label(self.root, text="", fg="blue", justify="left")
        self.response_label.pack(pady=10)

        # ========= Existing frame for searching accounts =========
        search_frame = tk.LabelFrame(self.root, text="Search Accounts")
        search_frame.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(search_frame, text="Pattern (wildcard):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        tk.Entry(search_frame, textvariable=self.search_pattern_var, width=30).grid(row=0, column=1, padx=5, pady=5)

        search_btn = tk.Button(search_frame, text="Search", command=self.on_search_accounts)
        search_btn.grid(row=0, column=2, padx=5, pady=5)

        # A label (or text widget) to display the current list of found accounts
        self.search_results_label = tk.Label(search_frame, text="", anchor="w", justify="left")
        self.search_results_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        # Buttons for going backward/forward through search results
        nav_frame = tk.Frame(search_frame)
        nav_frame.grid(row=2, column=0, columnspan=3, pady=5)
        prev_btn = tk.Button(nav_frame, text="Previous", command=self.on_previous_page)
        prev_btn.pack(side="left", padx=10)
        next_btn = tk.Button(nav_frame, text="Next", command=self.on_next_page)
        next_btn.pack(side="left", padx=10)

        # ========= Existing frame for reading messages =========
        messages_frame = tk.LabelFrame(self.root, text="Incoming Messages")
        messages_frame.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(messages_frame, text="How many messages to fetch at a time:").pack(anchor="w", padx=5, pady=2)
        tk.Entry(messages_frame, textvariable=self.fetch_count_var, width=10).pack(anchor="w", padx=5, pady=2)

        fetch_btn = tk.Button(messages_frame, text="Fetch Messages", command=self.on_fetch_messages)
        fetch_btn.pack(anchor="w", padx=5, pady=5)

        # A Text widget to display incoming messages
        self.incoming_messages_text = tk.Text(messages_frame, width=60, height=10, state="disabled")
        self.incoming_messages_text.pack(fill="both", expand=True, padx=5, pady=5)

        # ========= Delete Messages Frame =========
        delete_frame = tk.LabelFrame(self.root, text="Delete Messages")
        delete_frame.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(delete_frame, text="Enter Message IDs (comma-separated):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.delete_ids_var = tk.StringVar()
        tk.Entry(delete_frame, textvariable=self.delete_ids_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        delete_btn = tk.Button(delete_frame, text="Delete Messages", command=self.on_delete_messages)
        delete_btn.grid(row=0, column=2, padx=5, pady=5)

    def on_login_click(self) -> None:
        """
        Handle login button click event.
        Sets the action to 'login' and invokes the send click handler.
        """
        self.action_var.set("login")
        self.on_send_click()

    def on_register_click(self) -> None:
        """
        Handle register button click event.
        Sets the action to 'register' and invokes the send click handler.
        """
        self.action_var.set("register")
        self.on_send_click()

    def on_send_message_click(self) -> None:
        """
        Handle send message button click event.
        Sets the action to 'message' and invokes the send click handler.
        """
        self.action_var.set("message")
        self.on_send_click()

    def on_send_click(self) -> None:
        """
        Handle sending requests to the server.
        Retrieves values from GUI fields, sends request via ChatClient,
        and displays the response. Also handles special cases for messaging
        and login actions.
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
            resp_dict: Dict[str, Any] = self.client.send_request(
                action, from_user, to_user, password, msg
            )
            self.response_label.config(text=f"Server responded with dict:\n{resp_dict}")
            # If the action is "message", display the sent message in the message box.
            if action == "message":
                self._append_incoming_messages(f"To {to_user}: {msg}\n")
                # Optionally, clear the message entry field after sending.
                self.message_var.set("")
            # REAL-TIME MOD: After a successful login, start the persistent listener.
            if action == "login" and "session_id" in resp_dict:
                # Retrieve the unread message count (default to 0 if not provided)
                unread = resp_dict.get("unread_messages", 0)
                # Update the response label to show the unread messages count
                self.response_label.config(text=f"Login successful. You have {unread} unread messages.")
                self.client.start_listener(from_user, self.handle_incoming_message)

        except ConnectionRefusedError:
            self.response_label.config(text="Could not connect to server. Is it running?")
        except Exception as e:
            self.response_label.config(text=f"Error: {str(e)}")

    def on_search_accounts(self) -> None:
        """
        Handle account search functionality.
        Sends a request to the server to find accounts matching the search pattern.
        Updates the GUI with the search results.
        """
        pattern = self.search_pattern_var.get().strip()
        if not pattern:
            self.search_results_label.config(text="Please enter a pattern to search.")
            return

        try:
            # We assume the server has an action "list_accounts" that takes
            # the pattern in the 'message' field, for instance.
            resp_dict = self.client.send_request(
                action="list_accounts",
                from_user=self.from_var.get().strip(),
                to_user="",  # not used for listing
                password=self.password_var.get().strip(),
                msg=pattern
            )

            if resp_dict.get("status") == "ok":
                # The server might return {"status": "ok", "accounts": [...]}
                self.search_results = resp_dict.get("accounts", [])
                self.search_results_index = 0
                self.update_search_results_display()
            else:
                # Some error from the server
                self.search_results_label.config(
                    text=f"Error from server: {resp_dict.get('error', 'Unknown error')}"
                )
        except Exception as e:
            self.search_results_label.config(text=f"Search failed: {str(e)}")

    def update_search_results_display(self) -> None:
        """
        Update the GUI to show the current page of search results.
        Displays results_per_page number of results starting from the current index.
        """
        if not self.search_results:
            self.search_results_label.config(text="No results.")
            return

        start_idx = self.search_results_index
        end_idx = start_idx + self.results_per_page
        page_results = self.search_results[start_idx:end_idx]

        # Format them nicely
        display_text = "\n".join(page_results)
        page_info = f"Showing {start_idx+1}-{min(end_idx, len(self.search_results))} of {len(self.search_results)}"

        self.search_results_label.config(text=f"{page_info}\n{display_text}")

    def on_next_page(self) -> None:
        """
        Handle next page button click for search results.
        Advances to the next page of results if available.
        """
        if self.search_results_index + self.results_per_page < len(self.search_results):
            self.search_results_index += self.results_per_page
            self.update_search_results_display()

    def on_previous_page(self) -> None:
        """
        Handle previous page button click for search results.
        Goes back to the previous page of results if available.
        """
        if self.search_results_index - self.results_per_page >= 0:
            self.search_results_index -= self.results_per_page
            self.update_search_results_display()

    def on_fetch_messages(self) -> None:
        """
        Handle fetching messages from the server.
        Retrieves the specified number of undelivered messages for the current user
        and displays them in the messages text box.
        """
        if not self.from_var.get().strip():
            self._append_incoming_messages("Please specify your username in the 'From' field.\n")
            return

        try:
            count_str = self.fetch_count_var.get().strip()
            count_val = int(count_str)
        except ValueError:
            self._append_incoming_messages("Invalid number of messages.\n")
            return

        try:
            # We assume the server has an action "read_messages" that uses
            # 'message' field or something to indicate how many to fetch.
            resp_dict = self.client.send_request(
                action="read_messages",
                from_user=self.from_var.get().strip(),
                to_user="",  # not used for reading
                password=self.password_var.get().strip(),
                msg=str(count_val)  # Send the count as the message payload
            )

            if resp_dict.get("status") == "ok":
                # The server might return {"status": "ok", "messages": [...]}
                msgs = resp_dict.get("messages", [])
                if msgs:
                    for m in msgs:
                        msg_id = m.get("id", "N/A")
                        frm = m.get("from_user", "unknown")
                        content = m.get("content", "")
                        self._append_incoming_messages(f"ID {msg_id}: From {frm}: {content}\n")
                else:
                    self._append_incoming_messages("No new messages.\n")
            else:
                error_text = resp_dict.get("error", "Unknown error")
                self._append_incoming_messages(f"Error fetching messages: {error_text}\n")
        except Exception as e:
            self._append_incoming_messages(f"Failed to fetch messages: {str(e)}\n")

    def on_delete_messages(self) -> None:
        """
        Handle message deletion functionality.
        Sends a request to delete messages with specified IDs and updates
        the message display accordingly.
        """
        msg_ids_str = self.delete_ids_var.get().strip()
        print(msg_ids_str)
        if not msg_ids_str:
            self.response_label.config(text="Please enter message IDs to delete.")
            return

        try:
            resp_dict: Dict[str, Any] = self.client.send_request(
                action="delete_messages",
                from_user=self.from_var.get().strip(),
                to_user="",
                password=self.password_var.get().strip(),
                msg=msg_ids_str
            )
            if resp_dict.get("status") == "ok":
                self.response_label.config(text=resp_dict.get("message", "Messages deleted."))
                # Refresh the incoming messages text widget with the remaining messages.
                self.incoming_messages_text.config(state="normal")
                self.incoming_messages_text.delete(1.0, tk.END)
                messages = resp_dict.get("messages", [])
                if messages:
                    for m in messages:
                        msg_id = m.get("id", "N/A")
                        frm = m.get("from_user", "unknown")
                        content = m.get("content", "")
                        self.incoming_messages_text.insert(tk.END, f"ID {msg_id}: From {frm}: {content}\n")
                else:
                    self.incoming_messages_text.insert(tk.END, "No new messages.\n")
                self.incoming_messages_text.config(state="disabled")
                # Clear the delete message IDs entry.
                self.delete_ids_var.set("")
            else:
                self.response_label.config(text=f"Error deleting messages: {resp_dict.get('error')}")
        except Exception as e:
            self.response_label.config(text=f"Error: {str(e)}")

    def on_delete_account(self) -> None:
        """
        Handle account deletion functionality.
        Sends a request to delete the current user's account after validation.
        """
        username = self.from_var.get().strip()
        if not username:
            self.response_label.config(text="Please enter your username to delete your account.")
            return

        try:
            # resp_dict: Dict[str, Any] = self.client.delete_account(username)
            resp_dict: Dict[str, Any] = self.client.send_request(
                action="delete_account",
                from_user=self.from_var.get().strip(),
                to_user="",
                password=self.password_var.get().strip(),
                msg=""
            )
            if resp_dict.get("status") == "ok":
                self.response_label.config(text="Account has been deleted, close app to finish.")
            else:
                error = resp_dict.get("error", "Unknown error")
                self.response_label.config(text=f"Error deleting account: {error}")
        except Exception as e:
            self.response_label.config(text=f"Error: {str(e)}")

    def _append_incoming_messages(self, text: str) -> None:
        """
        Helper method to append text to the read-only text box for incoming messages.
        
        Args:
            text (str): The text to append to the messages display
        """
        if not self.incoming_messages_text:
            return
        self.incoming_messages_text.config(state="normal")
        self.incoming_messages_text.insert(tk.END, text)
        self.incoming_messages_text.config(state="disabled")
        self.incoming_messages_text.see(tk.END)  # auto-scroll

    def handle_incoming_message(self, msg_dict: Dict[str, Any]) -> None:
        """
        Callback for handling real-time messages from the persistent listener connection.
        Updates the GUI safely from the background thread using root.after.
        
        Args:
            msg_dict (Dict[str, Any]): Dictionary containing the message data
        """
        def update_gui():
            if msg_dict.get("status") == "ok" and "message" in msg_dict and "from_user" in msg_dict:
                self._append_incoming_messages(f"From {msg_dict['from_user']}: {msg_dict['message']}\n")
                print("printing msg_dict")
                print(msg_dict)
            elif msg_dict.get("status") == "error":
                self._append_incoming_messages(f"Real-time error: {msg_dict.get('error')}\n")
            else:
                self._append_incoming_messages(f"Real-time: {msg_dict}\n")
        self.root.after(0, update_gui)
