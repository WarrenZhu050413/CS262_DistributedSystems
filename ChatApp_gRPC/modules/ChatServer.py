import grpc
from concurrent import futures
import secrets
import sqlite3
import bcrypt
import ssl
import queue
import logging
from ChatApp_gRPC.modules.config import HOST, PORT, CERT_FILE, KEY_FILE, DB_FILE, LOG_FILE
from ChatApp_gRPC.proto_generated import chat_pb2
from ChatApp_gRPC.proto_generated import chat_pb2_grpc
from ChatApp_gRPC.proto_generated.chat_pb2_grpc import add_ChatServiceServicer_to_server

# Changed message_list into a protobuf list of ChatMessage objects.
# Changed name to ChatServiceServicer.
# Make sure that everything is in the correct type. Things are converted to int if they are actually ints.

from typing import Dict
class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):
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
        self.listeners: Dict[str, queue.Queue] = {}

        # Set up logging
        self.log_file: str = log_file
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.setup_logging()

        # Whether the server is running
        self.running: bool = False

        # Set up the database
        self.setup_database()

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
            self.logger.info("Returning from Register: %s", result)
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
            self.logger.info("Returning from Register: %s", result)
            self.logger.info("Usernames in DB: %s", self.get_all_usernames())
            return chat_pb2.RegisterResponse(status=result["status"], error=result["error"])

        hashed_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pass))
            conn.commit()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from Register: %s", result)
            return chat_pb2.RegisterResponse(status=result["status"], error=result["error"])

        conn.close()
        result = {"status": "ok", "message": "Registration successful"}
        self.logger.info("Returning from Register: %s", result)
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
            self.logger.info("Returning from Login: %s", result)
            return chat_pb2.LoginResponse(status=result["status"], error=result["error"])

        stored_hashed_pass = row[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_pass.encode('utf-8')):
            result = {"status": "error", "error": "Invalid username or password"}
            self.logger.info("Returning from Login: %s", result)
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
        self.logger.info("Returning from Login: %s", result)
        return chat_pb2.LoginResponse(status=result["status"], session_id=result['session_id'], unread_messages=int(result['unread_messages']))


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
            self.logger.info("Returning from SendMessage: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from SendMessage: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])
        
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (to_user,))
        row = c.fetchone()

        if row is None:
            conn.close()
            result = {"status": "error", "error": "Recipient does not exist"}
            self.logger.info("Returning from SendMessage: %s", result)
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
            self.logger.info("Returning from SendMessage: %s", result)
            return chat_pb2.SendMessageResponse(status=result["status"], error=result["error"])

        if to_user in self.listeners:
            # listener_data = self.listeners[to_user]
            try:
                push_obj = chat_pb2.PushObject(status="ok", from_user=from_user, content=msg)
                self.listener_q.put(push_obj)
                c.execute("UPDATE messages SET delivered=1 WHERE id=?", (message_id,))
                conn.commit()
                conn.close()
                result = {"status": "ok", "message": f"Message delivered to {to_user} in real-time"}
                self.logger.info("Returning from SendMessage: %s", result)
                return chat_pb2.SendMessageResponse(status=result["status"], content=result["message"])
            except Exception as e:
                self.logger.error(f"Real-time delivery failed: {str(e)}")
                conn.close()
                result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
                self.logger.info("Returning from SendMessage: %s", result)
                return chat_pb2.SendMessageResponse(status=result["status"], content=result["message"])
        else:
            conn.close()
            result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
            self.logger.info("Returning from SendMessage: %s", result)
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
            self.logger.info("Returning from ReadMessages: %s", result)
            return chat_pb2.ReadMessagesResponse(status=result["status"], error=result["error"])

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from ReadMessages: %s", result)
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
            self.logger.info("Returning from ReadMessages: %s", result)
            return chat_pb2.ReadMessagesResponse(status=result["status"], error=result["error"])

        messages_list = []
        for row in rows:
            _id, from_user_db, content = row
            message = chat_pb2.ChatMessage(
                id=int(_id),
                from_user=from_user_db,
                content=content
            )
            messages_list.append(message)

        conn.close()

        result = {"status": "ok", "messages": messages_list}
        self.logger.info("Returning from ReadMessages: %s", result)
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
            self.logger.info("Returning from ListAccounts: %s", result)
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
            self.logger.info("Returning from ListAccounts: %s", result)
            return chat_pb2.ListAccountsResponse(status=result["status"], error=result["error"])

        accounts = [r[0] for r in rows]
        conn.close()

        result = {"status": "ok", "accounts": accounts}
        self.logger.info("Returning from ListAccounts: %s", result)
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
            self.logger.info("Returning from DeleteMessages: %s", result)
            return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])
        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from DeleteMessages: %s", result)
            return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])

        # Parse the comma-separated message IDs.
        try:
            ids = [int(x.strip()) for x in msg_ids_str.split(',') if x.strip()]
            print(ids)
            if not ids:
                result = {"status": "error", "error": "No valid message IDs provided"}
                self.logger.info("Returning from DeleteMessages: %s", result)
                return chat_pb2.DeleteMessagesResponse(status=result["status"], error=result["error"])
        except Exception as e:
            result = {"status": "error", "error": f"Invalid message IDs: {str(e)}"}
            self.logger.info("Returning from DeleteMessages: %s", result)
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
                id=int(_id),
                from_user=from_user_db,
                content=content
            )
            messages_list.append(message)
        conn.close()

        result = {"status": "ok", "message": f"Deleted messages: {ids}", "messages": messages_list}
        self.logger.info("Returning from DeleteMessages: %s", result)
        return chat_pb2.DeleteMessagesResponse(status=result["status"], content=result["message"], messages=result["messages"])
    
    def DeleteAccount(self, request, context):
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
        username = request.username
        session_id = request.session_id

        # Validate the session.
        if not session_id or session_id not in self.active_sessions or self.active_sessions[session_id] != username:
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from DeleteAccount: %s", result)
            return chat_pb2.DeleteAccountResponse(status=result["status"], error=result["error"])

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
            self.logger.info("Returning from DeleteAccount: %s", result)
            return chat_pb2.DeleteAccountResponse(status=result["status"], error=result["error"])

        # Remove the session.
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        # Remove any persistent listener for this user.
        if username in self.listeners:
            del self.listeners[username]

        result = {"status": "ok", "content": "Account has been deleted, close app to finish."}
        self.logger.info("Returning from DeleteAccount: %s", result)
        return chat_pb2.DeleteAccountResponse(status=result["status"], content=result["content"])

    def Listen(self, request, context):
        # Validate session, ensure request.username matches a valid session, etc.
        username = request.username
        session_id = request.session_id
        if session_id not in self.active_sessions or \
           self.active_sessions[session_id] != username:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Invalid session.")
            return  # Ends the stream immediately.

        # Create a queue so we can push messages from SendMessage
        # or anywhere else. The Listen method will yield from that queue.
        q = queue.Queue()
        self.listeners[username] = q

        try:
            while True:
                # If the client disappears or cancels, context.is_active() becomes False
                if not context.is_active():
                    break

                # Block until we get a new ChatMessage or a sentinel to close
                try:
                    msg = q.get(timeout=1.0)  # or some short timeout
                except queue.Empty:
                    continue

                # 'msg' should be a chat_pb2.ChatMessage
                yield msg

        finally:
            # Clean up if the client stops listening
            if username in self.listeners and self.listeners[username] == q:
                del self.listeners[username]