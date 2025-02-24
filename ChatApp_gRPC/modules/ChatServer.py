import grpc
from concurrent import futures
import logging
import sqlite3
import bcrypt
import secrets
import socket
import selectors
import types
import sqlite3
import bcrypt
import secrets
import ssl
import logging
from generated import chat_pb2, chat_pb2_grpc

# Changed message_list into a protobuf list of ChatMessage objects.

from typing import Dict
from .WireMessageBinary import WireMessageBinary
class ChatServerServicer(chat_pb2_grpc.ChatServiceServicer):
    """
    A secure chat server implementation that handles multiple concurrent client connections.
    
    This server provides:
    - TLS encryption for all communications
    - User registration and authentication
    - Real-time message delivery when recipients are online
    - Message storage and delayed delivery for offline recipients
    - Account management features like listing users and deleting accounts
    - Message management including reading and deleting messages
    
    The server uses:
    - Non-blocking sockets with selectors for concurrent I/O
    - SQLite for persistent storage of users and messages
    - bcrypt for secure password hashing
    - Binary wire protocol for efficient message encoding
    
    Key Features:
    - Secure communication using TLS
    - User authentication and session management
    - Real-time and offline message delivery
    - Account and message management
    - Concurrent client handling
    - Persistent message storage
    - Comprehensive logging

    How it works:
    Uses accept_wrapper() to accept new connections.
    Uses service_connection() to handle events on client connections.
    Uses _handle_read() to process incoming data from a client connection.
    Uses _handle_write() to send queued outgoing data to a client.

    _handle_read() uses handle_request() to route and handle client 
    requests to different helper functions depending on the user request.
    
    Then the server response is encoded using WireMessageBinary and added 
    to the outgoing buffer to be sent to the client in _handle_write().
    """

    def __init__(self, host: str, port: int, db_file: str, cert_file: str, key_file: str, log_file: str) -> None:
        """
        Initialize the chat server with required configuration.

        Args:
            host (str): The hostname/IP to bind the server to
            port (int): The port number to listen on
            db_file (str): Path to SQLite database file
            cert_file (str): Path to TLS certificate file
            key_file (str): Path to TLS private key file
            log_file (str): Path to log file

        The server maintains several key data structures:
            - active_sessions: Maps session IDs to usernames
            - listeners: Maps usernames to their real-time connection data
            - sel: Selector for handling concurrent I/O operations
        """
        self.host: str = host
        self.port: int = port
        self.db_file: str = db_file
        self.cert_file: str = cert_file
        self.key_file: str = key_file
        
        # In-memory session storage: session_id -> username
        self.active_sessions: Dict[str, str] = {}
        # REAL-TIME MOD: Dictionary mapping usernames to their persistent listener connection data
        self.listeners: Dict[str, any] = {}

        # Selector for handling concurrent I/O
        self.sel: selectors.DefaultSelector = selectors.DefaultSelector()

        # Set up logging
        self.log_file: str = log_file
        self.logger: logging.Logger = logging.getLogger(__name__)

        # Whether the server is running
        self.running: bool = False

    def setup_logging(self):
        """
        Configure logging settings for the server.
        
        Sets up logging with:
        - DEBUG level logging (can be changed to INFO in production)
        - Log file output
        - Timestamp, level and message formatting
        """
        logging_level = logging.DEBUG  # Can also be INFO in production
        logging_file = self.log_file
        logging_format = "%(asctime)s - %(levelname)s - %(message)s"

        logging.basicConfig(
            level=logging_level,
            filename=logging_file,
            format=logging_format
        )

    def setup_database(self):
        """
        Initialize the SQLite database schema.
        
        Creates two tables if they don't exist:
        1. users table:
           - username: TEXT PRIMARY KEY
           - password: TEXT (bcrypt hashed)
           
        2. messages table:
           - id: INTEGER PRIMARY KEY AUTOINCREMENT
           - from_user: TEXT NOT NULL
           - to_user: TEXT NOT NULL  
           - content: TEXT NOT NULL
           - delivered: INTEGER NOT NULL DEFAULT 0
           
        The delivered flag in messages table:
        - 0 = message not yet delivered
        - 1 = message delivered to recipient
        """
        self.logger.info("Setting up database...")
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT
            )
        """)
        # New table for storing messages.
        # 'delivered' will be 0 if undelivered, 1 if delivered.
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                content TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def accept_wrapper(self, sock, context):
        """
        Accept and configure new client connections.
        
        Args:
            sock: The listening socket
            context: The SSL context for TLS wrapping
            
        This method:
        1. Accepts the new connection
        2. Wraps it in TLS 
        3. Sets it to non-blocking mode
        4. Registers it with the selector
        
        The connection data includes:
        - addr: Client address
        - inb: Input buffer
        - outb: Output buffer
        - handshake_complete: TLS handshake status
        """
        conn, addr = sock.accept()
        self.logger.info(f"Accepted connection from {addr}")
        try:
            tls_conn = context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
        except ssl.SSLError as e:
            self.logger.error("TLS handshake failed: %s", e)
            conn.close()
            return

        tls_conn.setblocking(False)
        data = types.SimpleNamespace(
            addr=addr, 
            inb=b"", 
            outb=b"", 
            handshake_complete=False
        )

        self.sel.register(tls_conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)

    def service_connection(self, key, mask):
        """
        Handle I/O events on client connections.
        
        Args:
            key: The selector key containing socket and data
            mask: The event mask indicating read/write events
            
        This method:
        1. Completes TLS handshake if needed
        2. Handles read events by:
           - Reading data from socket
           - Processing complete messages
           - Generating responses
        3. Handles write events by:
           - Sending queued outgoing data
           
        Uses WireMessageBinary for message encoding/decoding.
        """
        tls_conn = key.fileobj
        data = key.data

        # Complete the TLS handshake if needed.
        if not data.handshake_complete and not self._complete_handshake(tls_conn, data):
            return

        if mask & selectors.EVENT_READ:
            self._handle_read(tls_conn, data, key)

        if mask & selectors.EVENT_WRITE:
            self._handle_write(tls_conn, data)

    def _complete_handshake(self, tls_conn: socket.socket, data) -> bool:
        """
        Complete the TLS handshake for a connection.
        
        Args:
            tls_conn: The TLS wrapped socket
            data: Connection data object
            
        Returns:
            bool: True if handshake completed, False if more I/O needed
            
        This method handles the non-blocking TLS handshake process,
        dealing with WantReadError/WantWriteError conditions.
        """
        try:
            tls_conn.do_handshake()
            data.handshake_complete = True
            self.logger.debug(f"Handshake complete for {data.addr}")
            return True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # Handshake is still in progress.
            return False
        except (OSError, ssl.SSLError) as e:
            self._close_connection(tls_conn, data, f"TLS handshake failed: {e}")
            return False

    def _handle_read(self, tls_conn: socket.socket, data, key) -> None:
        """
        Process incoming data from a client connection.
        
        Args:
            tls_conn: The TLS wrapped socket
            data: Connection data object
            key: Selector key
            
        This method:
        1. Reads raw data from the socket
        2. Buffers incomplete messages
        3. Processes complete messages by:
           - Extracting length-prefixed messages
           - Parsing binary wire format
           - Dispatching to appropriate handler
           - Queueing responses
        """
        try:
            recv_data = tls_conn.recv(4096)  # Read up to 4KB
        except ssl.SSLWantReadError:
            return
        except ssl.SSLError as e:
            self._close_connection(tls_conn, data, f"TLS read error: {e}")
            return
        except ConnectionResetError:
            recv_data = None

        if recv_data:
            data.inb += recv_data
        else:
            self._close_connection(tls_conn, data, f"Closing connection to {data.addr}")
            return

        # Process all complete (length-prefixed) messages in the input buffer.
        while True:
            if len(data.inb) < 4:
                break

            msg_len = int.from_bytes(data.inb[:4], "big")
            if len(data.inb) < 4 + msg_len:
                break

            raw_msg = data.inb[4:4+msg_len]
            data.inb = data.inb[4+msg_len:]

            try:
                request_obj = WireMessageBinary.parse_wire_message(raw_msg)
            except Exception as e:
                error_response = {"status": "error", "error": f"Dict parse error: {str(e)}"}
                self.queue_message(data, error_response)
                continue

            response_obj = self.handle_request(request_obj, key) # This is where the request is handled.
            response_bytes = WireMessageBinary.encode_message(response_obj)
            data.outb += response_bytes

    def _handle_write(self, tls_conn: socket.socket, data) -> None:
        """
        Send queued outgoing data to a client.
        
        Args:
            tls_conn: The TLS wrapped socket
            data: Connection data object
            
        Handles non-blocking sends and TLS-specific write conditions.
        Removes sent data from the outgoing buffer.
        """
        if data.outb:
            try:
                sent = tls_conn.send(data.outb)
                data.outb = data.outb[sent:]
            except ssl.SSLWantWriteError:
                return
            except ssl.SSLError as e:
                self._close_connection(tls_conn, data, f"TLS write error: {e}")

    def _close_connection(self, tls_conn: socket.socket, data, error_message: str) -> None:
        """
        Clean up and close a client connection.
        
        Args:
            tls_conn: The TLS wrapped socket to close
            data: Connection data object
            error_message: Message to log
            
        This method:
        1. Removes any persistent listener registration
        2. Logs the closure reason
        3. Unregisters from the selector
        4. Closes the socket
        """
        if hasattr(data, 'username'):
            if data.username in self.listeners and self.listeners[data.username] is data:
                del self.listeners[data.username]
        # Log as INFO if the message indicates a normal connection close.
        if error_message.startswith("Closing connection"):
            self.logger.info(error_message)
        else:
            self.logger.error(error_message)
        self.sel.unregister(tls_conn)
        tls_conn.close()

    def queue_message(self, data, response_obj) -> None:
        """
        Queue a response message for sending.
        
        Args:
            data: Connection data object
            response_obj: Response dictionary to encode and queue
            
        Encodes the response using WireMessageBinary and adds
        it to the connection's outgoing buffer.
        """
        response_bytes = WireMessageBinary.encode_message(response_obj)
        data.outb += response_bytes

    # def handle_request(self, req, key):
    #     """
    #     Route and handle client requests.
        
    #     Args:
    #         req: The decoded request dictionary
    #         key: Selector key for the connection
            
    #     Returns:
    #         dict: Response object to send back to client
            
    #     Supports these actions:
    #     - register: Create new user account
    #     - login: Authenticate and create session
    #     - message: Send message to another user
    #     - list_accounts: List matching usernames
    #     - read_messages: Retrieve undelivered messages
    #     - listen: Register for real-time messages
    #     - delete_messages: Remove messages
    #     - delete_account: Remove user account
    #     """
    #     action = req.get("action", "").lower()
    #     if action == "register":
    #         username = req.get("from_user", "")
    #         password = req.get("password", "")
    #         return self.handle_register(username, password)

    #     elif action == "login":
    #         username = req.get("from_user", "")
    #         password = req.get("password", "")
    #         return self.handle_login(username, password)

    #     elif action == "message":
    #         session_id = req.get("session_id")
    #         from_user = req.get("from_user", "")
    #         to_user = req.get("to_user", "")
    #         message = req.get("message", "")
    #         return self.handle_message(session_id, from_user, to_user, message)

    #     elif action == "list_accounts":
    #         session_id = req.get("session_id")
    #         pattern = req.get("message", "")
    #         return self.handle_list_accounts(session_id, pattern)

    #     elif action == "read_messages":
    #         session_id = req.get("session_id")
    #         from_user = req.get("from_user", "")
    #         count_str = req.get("message", "")
    #         return self.handle_read_messages(session_id, from_user, count_str)

    #     elif action == "listen":
    #         username = req.get("from_user", "")
    #         session_id = req.get("session_id")
    #         if not session_id or session_id not in self.active_sessions or self.active_sessions[session_id] != username:
    #             result = {"status": "error", "error": "Invalid session for listening"}
    #             self.logger.info("Returning from handle_request (listen): %s", result)
    #             return result
    #         key.data.username = username
    #         self.listeners[username] = key.data
    #         result = {"status": "ok", "message": "Listening for real-time messages"}
    #         self.logger.info("Returning from handle_request (listen): %s", result)
    #         return result
    
    #     elif action == "delete_messages":
    #         session_id = req.get("session_id")
    #         from_user = req.get("from_user", "")
    #         msg_ids_str = req.get("message", "")
    #         return self.handle_delete_messages(session_id, from_user, msg_ids_str)
        
    #     elif action == "delete_account":
    #         session_id = req.get("session_id")
    #         username = req.get("from_user", "")
    #         return self.handle_delete_account(username, session_id)

    #     else:
    #         result = {"status": "error", "error": f"Unknown action: {action}"}
    #         self.logger.info("Returning from handle_request (unknown action): %s", result)
    #         return result
        

    def get_all_usernames(self):
        """
        Retrieve all registered usernames from database.
        
        Returns:
            list: List of all usernames in the database
            
        Used primarily for debugging and account listing.
        """
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in rows]

    def Register(self, request, context):
        """
        Register a new user account.
        
        Args:
            request: RegisterRequest object
            context: gRPC context
            
        Returns:
            RegisterResponse object
            
        The password is hashed using bcrypt before storage.
        Validates:
        - Password length
        - Username uniqueness
        """
        username = request.username
        password = request.password

        if len(password) >= 256:
            result = {"status": "error", "error": "Password is too long"}
            self.logger.info("Returning from handle_register: %s", result)
            return chat_pb2.RegisterResponse(status=result["status"], error=result["error"])

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        self.logger.debug(f"Usernames before registration: {self.get_all_usernames()}")
        self.logger.debug(f"Registering username: {username}")

        if row is not None:
            conn.close()
            result = {"status": "error", "error": "Username already exists"}
            self.logger.info("Returning from handle_register: %s", result)
            self.logger.info("Usernames in DB: %s", self.get_all_usernames())
            return chat_pb2.RegisterResponse(status=result["status"], error=result["error"])

        hashed_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pass))
            conn.commit()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_register: %s", result)
            return chat_pb2.RegisterResponse(status=result["status"], error=result["error"])

        conn.close()
        result = {"status": "ok", "message": "Registration successful"}
        self.logger.info("Returning from handle_register: %s", result)
        return chat_pb2.RegisterResponse(status=result["status"], content=result["message"])

    def Login(self, request, context):
        """
        Authenticate a user and create a session.
        
        Args:
            request: LoginRequest object
            context: gRPC context
            
        Returns:
            LoginResponse object
            
        On successful login:
        1. Verifies username/password
        2. Creates new session ID
        3. Counts unread messages
        4. Returns session ID and unread count
        """
        username = request.username
        password = request.password

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            result = {"status": "error", "error": "Invalid username or password"}
            self.logger.info("Returning from handle_login: %s", result)
            return chat_pb2.LoginResponse(status=result["status"], error=result["error"])

        stored_hashed_pass = row[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_pass.encode('utf-8')):
            result = {"status": "error", "error": "Invalid username or password"}
            self.logger.info("Returning from handle_login: %s", result)
            return chat_pb2.LoginResponse(status=result["status"], error=result["error"])

        session_id = secrets.token_hex(16)
        self.active_sessions[session_id] = username
        self.logger.info(f"Created session ID: {session_id} for user: {username}")

        # --- NEW: Count unread (undelivered) messages for this user ---
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM messages WHERE to_user=? AND delivered=0", (username,))
        unread_count = c.fetchone()[0]
        conn.close()

        result = {"status": "ok", "session_id": session_id, "unread_messages": unread_count}
        self.logger.info("Returning from handle_login: %s", result)
        return chat_pb2.LoginResponse(status=result["status"], session_id=result['session_id'], unread_messages=result['unread_messages'])


    def SendMessage(self, request, context):
        """
        Process a message send request.
        
        Args:
            session_id: Sender's session ID
            from_user: Sender's username
            to_user: Recipient's username
            msg: Message content
            
        Returns:
            dict: Response indicating delivery status
            
        This method:
        1. Validates the session
        2. Verifies recipient exists
        3. Stores message in database
        4. Attempts real-time delivery if recipient is listening
        5. Marks message as delivered if real-time delivery succeeds
        """
        session_id = request.session_id
        from_user = request.from_user
        to_user = request.to_user
        msg = request.content

        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session: {session_id} from user: {from_user}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_message: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from handle_message: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])
        
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (to_user,))
        row = c.fetchone()

        if row is None:
            conn.close()
            result = {"status": "error", "error": "Recipient does not exist"}
            self.logger.info("Returning from handle_message: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])

        try:
            c.execute("""
                INSERT INTO messages (from_user, to_user, content, delivered) 
                VALUES (?, ?, ?, 0)
            """, (from_user, to_user, msg))
            message_id = c.lastrowid
            conn.commit()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_message: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])

        if to_user in self.listeners:
            listener_data = self.listeners[to_user]
            try:
                push_obj = {"status": "ok", "from_user": from_user, "message": msg}
                self.queue_message(listener_data, push_obj)
                c.execute("UPDATE messages SET delivered=1 WHERE id=?", (message_id,))
                conn.commit()
                conn.close()
                result = {"status": "ok", "message": f"Message delivered to {to_user} in real-time"}
                self.logger.info("Returning from handle_message: %s", result)
                return chat_pb2.SendMessageResponse(status=result["status"], message=result["message"])
            except Exception as e:
                self.logger.error(f"Real-time delivery failed: {str(e)}")
                conn.close()
                result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
                self.logger.info("Returning from handle_message: %s", result)
                return chat_pb2.SendMessageResponse(status=result["status"], content=result["message"])
        else:
            conn.close()
            result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
            self.logger.info("Returning from handle_message: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], content=result["message"])

    def ReadMessages(self, request, context):
        """
        Retrieve undelivered messages for a user.
        
        Args:
            session_id: User's session ID
            from_user: Username requesting messages
            count_str: Number of messages to retrieve
            
        Returns:
            dict: Response with list of messages
            
        This method:
        1. Validates session
        2. Retrieves undelivered messages
        3. Marks retrieved messages as delivered
        4. Returns messages with sender and content
        """
        session_id = request.session_id
        from_user = request.from_user
        count_str = request.count

        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session for read_messages: {session_id}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_read_messages: %s", result)
            return chat_pb2.ReadMessagesResponse(status=result["status"], error=result["error"])

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from handle_read_messages: %s", result)
            return chat_pb2.ReadMessagesResponse(status=result["status"], error=result["error"])

        try:
            count = int(count_str)
        except ValueError:
            count = 5

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        try:
            c.execute("""
                SELECT id, from_user, content 
                FROM messages 
                WHERE to_user=? AND delivered=0 
                ORDER BY id 
                LIMIT ?
            """, (from_user, count))
            rows = c.fetchall()
            msg_ids = [r[0] for r in rows]
            if msg_ids:
                c.executemany(
                    "UPDATE messages SET delivered=1 WHERE id=?",
                    [(mid,) for mid in msg_ids]
                )
            conn.commit()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_read_messages: %s", result)
            return chat_pb2.ReadMessagesResponse(status=result["status"], error=result["error"])

        messages_list = []
        for row in rows:
            _id, from_user_db, content = row
            message = chat_pb2.ChatMessage(
                id=_id,
                from_user=from_user_db,
                content=content
            )
            messages_list.append(message)

        conn.close()

        result = {"status": "ok", "messages": messages_list}
        self.logger.info("Returning from handle_read_messages: %s", result)
        return chat_pb2.ReadMessagesResponse(status=result["status"], messages=result["messages"])


    def ListAccounts(self, request, context):
        """
        List user accounts matching a pattern.
        
        Args:
            session_id: Requester's session ID
            pattern: Search pattern (supports * wildcard)
            
        Returns:
            dict: Response with list of matching usernames
            
        The pattern:
        - Empty pattern lists all users
        - * wildcard converted to SQL LIKE %
        - Returns usernames matching pattern
        """
        session_id = request.session_id
        pattern = request.pattern

        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session for list_accounts: {session_id}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_list_accounts: %s", result)
            return chat_pb2.ListAccountsResponse(status=result["status"], error=result["error"])

        if not pattern.strip():
            pattern = "%"
        else:
            if "*" in pattern:
                pattern = pattern.replace("*", "%")

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        try:
            c.execute("SELECT username FROM users WHERE username LIKE ?", (pattern,))
            rows = c.fetchall()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_list_accounts: %s", result)
            return chat_pb2.ListAccountsResponse(status=result["status"], error=result["error"])

        accounts = [r[0] for r in rows]
        conn.close()

        result = {"status": "ok", "accounts": accounts}
        self.logger.info("Returning from handle_list_accounts: %s", result)
        return chat_pb2.ListAccountsResponse(status=result["status"], accounts=result["accounts"])

    
    def DeleteMessages(self, request, context):
        """
        Delete specified messages for a user.
        
        Args:
            session_id: User's session ID
            from_user: Username requesting deletion
            msg_ids_str: Comma-separated list of message IDs
            
        Returns:
            dict: Response with remaining messages
            
        This method:
        1. Validates session
        2. Parses message IDs
        3. Deletes specified messages
        4. Returns remaining messages
        """
        session_id = request.session_id
        from_user = request.from_user
        msg_ids_str = request.message_ids

        # Validate session.
        if not session_id or session_id not in self.active_sessions:
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_delete_messages: %s", result)
            return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])
        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from handle_delete_messages: %s", result)
            return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])

        # Parse the comma-separated message IDs.
        try:
            ids = [int(x.strip()) for x in msg_ids_str.split(',') if x.strip()]
            print(ids)
            if not ids:
                result = {"status": "error", "error": "No valid message IDs provided"}
                self.logger.info("Returning from handle_delete_messages: %s", result)
                return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])
        except Exception as e:
            result = {"status": "error", "error": f"Invalid message IDs: {str(e)}"}
            self.logger.info("Returning from handle_delete_messages: %s", result)
            return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        placeholders = ','.join(['?'] * len(ids))
        # Only delete messages for this user.
        c.execute(f"DELETE FROM messages WHERE id IN ({placeholders}) AND to_user=?", (*ids, from_user))
        conn.commit()

        # Retrieve the delivered messages for this user. TODO: may need to tweak this?
        c.execute(
            "SELECT id, from_user, content FROM messages "
            "WHERE (to_user = ? AND delivered = 1) OR (from_user = ?) "
            "ORDER BY id",
            (from_user, from_user)
        )
        rows = c.fetchall()
        messages_list = []
        for row in rows:
            _id, from_user_db, content = row
            message = chat_pb2.ChatMessage(
                id=_id,
                from_user=from_user_db,
                content=content
            )
            messages_list.append(message)
        conn.close()

        result = {"status": "ok", "message": f"Deleted messages: {ids}", "messages": messages_list}
        self.logger.info("Returning from handle_delete_messages: %s", result)
        return chat_pb2.DeleteMessagesResponse(status=result["status"], content=result["message"], messages=result["messages"])
    
    def handle_delete_account(self, username, session_id):
        """
        Delete a user account and all associated data.
        
        Args:
            username: Username to delete
            session_id: User's session ID
            
        Returns:
            dict: Response indicating success/failure
            
        This method:
        1. Validates session
        2. Deletes user from database
        3. Deletes all messages to/from user
        4. Removes session and listener
        5. Returns success message
        """
        # Validate the session.
        if not session_id or session_id not in self.active_sessions or self.active_sessions[session_id] != username:
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_delete_account: %s", result)
            return result

        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            # Delete the user from the users table.
            c.execute("DELETE FROM users WHERE username = ?", (username,))
            # Delete all messages where the user is either the sender or recipient.
            c.execute("DELETE FROM messages WHERE from_user = ? OR to_user = ?", (username, username))
            conn.commit()
            conn.close()
        except Exception as e:
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_delete_account: %s", result)
            return result

        # Remove the session.
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        # Remove any persistent listener for this user.
        if username in self.listeners:
            del self.listeners[username]

        result = {"status": "ok", "message": "Account has been deleted, close app to finish."}
        self.logger.info("Returning from handle_delete_account: %s", result)
        return result

    def start(self):
        self.setup_logging()
        self.logger.info("Starting the server...")
        self.logger.debug("About to call setup_database()")
        self.setup_database()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
            # Enable address reuse to prevent "Address already in use" errors.
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind((self.host, self.port))
            lsock.listen()
            self.logger.debug(f"Listening on {self.host}:{self.port}")
            lsock.setblocking(False)
            self.sel.register(lsock, selectors.EVENT_READ, data=None)

            try:
                while self.running:
                    events = self.sel.select(timeout=None)
                    for key, mask in events:
                        if key.data is None:
                            self.accept_wrapper(key.fileobj, context)
                        else:
                            self.service_connection(key, mask)
            except KeyboardInterrupt:
                self.logger.info("Caught keyboard interrupt, exiting")
            finally:
                self.sel.close()

    def stop(self):
        self.logger.info("Stopping the server...")
        self.running = False