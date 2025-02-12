import json
import socket
import selectors
import types
import sqlite3
import bcrypt
import secrets
import ssl
import logging

from typing import Dict
from .WireMessageJSON import WireMessageJSON

class ChatServer:
    """
    A class-based refactoring of the chat server.
    Encapsulates the SSL, socket, and message-handling logic.
    """

    def __init__(self, host: str, port: int, db_file: str, cert_file: str, key_file: str, log_file: str) -> None:
        """
        Initialize the chat server with required configuration.
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
        Configure logging settings.
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
        Create a 'users' table in SQLite if it doesn't exist.
        Columns: username TEXT PRIMARY KEY, password TEXT (hashed password).
        
        NOTE: We also create a 'messages' table for storing undelivered messages,
        and any other tables we need (for example, for listing accounts).
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
        Accept an incoming connection and wrap it in SSL.
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
        Process I/O events on a TLS connection using non-blocking sockets.
        Uses WireMessageJSON for decoding incoming messages and encoding responses.
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
        Try to complete the TLS handshake.
        Returns True if successful, or False if more I/O is needed.
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
        Read available data from the socket, extract complete messages using
        WireMessageJSON.parse_wire_message(), dispatch the request, and queue
        the encoded response for sending.
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
                request_obj = WireMessageJSON.parse_wire_message(raw_msg)
            except json.JSONDecodeError as e:
                error_response = {"status": "error", "error": f"JSON parse error: {e}"}
                self.queue_json_message(data, error_response)
                continue

            response_obj = self.handle_json_request(request_obj, key)
            response_bytes = WireMessageJSON.encode_message(response_obj)
            data.outb += response_bytes

    def _handle_write(self, tls_conn: socket.socket, data) -> None:
        """
        Write queued outgoing data to the socket.
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
        Log a message, unregister the socket, remove any persistent listener,
        and close the connection.
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

    # NEW: Define queue_json_message method.
    def queue_json_message(self, data, response_obj) -> None:
        """
        Encode the response object and append it to the connection's outgoing buffer.
        """
        response_bytes = WireMessageJSON.encode_message(response_obj)
        data.outb += response_bytes

    def handle_json_request(self, req, key):
        action = req.get("action", "").lower()
        if action == "register":
            username = req.get("from_user", "")
            password = req.get("password", "")
            return self.handle_register(username, password)

        elif action == "login":
            username = req.get("from_user", "")
            password = req.get("password", "")
            return self.handle_login(username, password)

        elif action == "message":
            session_id = req.get("session_id")
            from_user = req.get("from_user", "")
            to_user = req.get("to_user", "")
            message = req.get("message", "")
            return self.handle_message(session_id, from_user, to_user, message)

        elif action == "list_accounts":
            session_id = req.get("session_id")
            pattern = req.get("message", "")
            return self.handle_list_accounts(session_id, pattern)

        elif action == "read_messages":
            session_id = req.get("session_id")
            from_user = req.get("from_user", "")
            count_str = req.get("message", "")
            return self.handle_read_messages(session_id, from_user, count_str)

        elif action == "listen":
            username = req.get("from_user", "")
            session_id = req.get("session_id")
            if not session_id or session_id not in self.active_sessions or self.active_sessions[session_id] != username:
                result = {"status": "error", "error": "Invalid session for listening"}
                self.logger.info("Returning from handle_json_request (listen): %s", result)
                return result
            key.data.username = username
            self.listeners[username] = key.data
            result = {"status": "ok", "message": "Listening for real-time messages"}
            self.logger.info("Returning from handle_json_request (listen): %s", result)
            return result

        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}
            self.logger.info("Returning from handle_json_request (unknown action): %s", result)
            return result

    def get_all_usernames(self):
        """
        Get all usernames from the database.
        """
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in rows]

    def handle_register(self, username, password):
        if len(password) >= 256:
            result = {"status": "error", "error": "Password is too long"}
            self.logger.info("Returning from handle_register: %s", result)
            return result

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
            return result

        hashed_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pass))
            conn.commit()
        except Exception as e:
            conn.close()
            result = {"status": "error", "error": f"Database error: {str(e)}"}
            self.logger.info("Returning from handle_register: %s", result)
            return result

        conn.close()
        result = {"status": "ok", "message": "Registration successful"}
        self.logger.info("Returning from handle_register: %s", result)
        return result

    def handle_login(self, username, password):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            result = {"status": "error", "error": "Invalid username or password"}
            self.logger.info("Returning from handle_login: %s", result)
            return result

        stored_hashed_pass = row[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_pass.encode('utf-8')):
            result = {"status": "error", "error": "Invalid username or password"}
            self.logger.info("Returning from handle_login: %s", result)
            return result

        session_id = secrets.token_hex(16)
        self.active_sessions[session_id] = username
        self.logger.info(f"Created session ID: {session_id} for user: {username}")

        result = {"status": "ok", "session_id": session_id}
        self.logger.info("Returning from handle_login: %s", result)
        return result

    def handle_message(self, session_id, from_user, to_user, msg):
        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session: {session_id} from user: {from_user}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_message: %s", result)
            return result

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from handle_message: %s", result)
            return result
        
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (to_user,))
        row = c.fetchone()

        if row is None:
            conn.close()
            result = {"status": "error", "error": "Recipient does not exist"}
            self.logger.info("Returning from handle_message: %s", result)
            return result

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
            return result

        if to_user in self.listeners:
            listener_data = self.listeners[to_user]
            try:
                push_obj = {"status": "ok", "from_user": from_user, "message": msg}
                self.queue_json_message(listener_data, push_obj)
                c.execute("UPDATE messages SET delivered=1 WHERE id=?", (message_id,))
                conn.commit()
                conn.close()
                result = {"status": "ok", "message": f"Message delivered to {to_user} in real-time"}
                self.logger.info("Returning from handle_message: %s", result)
                return result
            except Exception as e:
                self.logger.error(f"Real-time delivery failed: {str(e)}")
                conn.close()
                result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
                self.logger.info("Returning from handle_message: %s", result)
                return result
        else:
            conn.close()
            result = {"status": "ok", "message": f"Message stored for delivery to {to_user}"}
            self.logger.info("Returning from handle_message: %s", result)
            return result

    def handle_list_accounts(self, session_id, pattern):
        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session for list_accounts: {session_id}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_list_accounts: %s", result)
            return result

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
            return result

        accounts = [r[0] for r in rows]
        conn.close()

        result = {"status": "ok", "accounts": accounts}
        self.logger.info("Returning from handle_list_accounts: %s", result)
        return result

    def handle_read_messages(self, session_id, from_user, count_str):
        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session for read_messages: {session_id}")
            result = {"status": "error", "error": "Invalid session"}
            self.logger.info("Returning from handle_read_messages: %s", result)
            return result

        if from_user != self.active_sessions[session_id]:
            result = {"status": "error", "error": "Session does not match 'from' user"}
            self.logger.info("Returning from handle_read_messages: %s", result)
            return result

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
            return result

        messages_list = []
        for row in rows:
            _id, from_user_db, content = row
            messages_list.append({
                "from_user": from_user_db,
                "content": content
            })

        conn.close()

        result = {"status": "ok", "messages": messages_list}
        self.logger.info("Returning from handle_read_messages: %s", result)
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
