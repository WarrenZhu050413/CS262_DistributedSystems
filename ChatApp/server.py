#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import socket
import selectors
import types
import sqlite3
import bcrypt
import secrets
import ssl
import logging

from config import HOST, PORT, DB_FILE

class ChatServer:
    """
    A class-based refactoring of the chat server.
    Encapsulates the SSL, socket, and message-handling logic.
    """

    def __init__(self, host, port, db_file, cert_file, key_file, log_file="./logging/server.log"):
        """
        Initialize the chat server with required configuration.
        """
        self.host = host
        self.port = port
        self.db_file = db_file
        self.cert_file = cert_file
        self.key_file = key_file
        
        # In-memory session storage: session_id -> username
        self.active_sessions = {}

        # Selector for handling concurrent I/O
        self.sel = selectors.DefaultSelector()

        # Set up logging
        self.log_file = log_file
        self.logger = logging.getLogger(__name__)

    def setup_logging(self):
        """
        Configure logging settings.
        """
        logging.basicConfig(
            level=logging.DEBUG,  # or logging.INFO in production
            filename=self.log_file,
            format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
        )

    def setup_database(self):
        """
        Create a 'users' table in SQLite if it doesn't exist.
        Columns: username TEXT PRIMARY KEY, password TEXT (hashed password).
        """
        self.logger.debug("Setting up database...")
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT
            )
        """)
        conn.commit()
        conn.close()

    def accept_wrapper(self, sock, context):
        """
        Accept an incoming connection and wrap it in SSL.
        """
        conn, addr = sock.accept()
        self.logger.debug(f"Accepted connection from {addr}")
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
        Service a client connection for read/write events.
        """
        tls_conn = key.fileobj
        data = key.data

        # 1) If the handshake hasn't completed, try to do it.
        if not data.handshake_complete:
            try:
                tls_conn.do_handshake()
                data.handshake_complete = True  # success!
                self.logger.debug(f"Handshake complete for {data.addr}")
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # We need more reads/writes; return and wait for next event
                return
            except (OSError, ssl.SSLError) as e:
                # Hard error, close
                self.logger.error("TLS handshake failed: %s", e)
                self.sel.unregister(tls_conn)
                tls_conn.close()
                return

        # Handle readable socket
        if mask & selectors.EVENT_READ:
            try:
                recv_data = tls_conn.recv(4096)  # read up to 4KB
            except ssl.SSLWantReadError:
                return
            except ssl.SSLError as e:
                self.logger.error("TLS read error: %s", e)
                self.sel.unregister(tls_conn)
                tls_conn.close()
                return
            except ConnectionResetError:
                recv_data = None

            if recv_data:
                data.inb += recv_data
            else:
                self.logger.debug(f"Closing connection to {data.addr}")
                self.sel.unregister(tls_conn)
                tls_conn.close()
                return

            # Process all complete (length-prefixed) messages in data.inb
            while True:
                if len(data.inb) < 4:
                    # Not enough bytes for length prefix
                    break

                # Parse the next length (4 bytes, big-endian)
                msg_len = int.from_bytes(data.inb[:4], "big")
                if len(data.inb) < 4 + msg_len:
                    # We don't have the full message yet
                    break

                # Extract the message
                raw_msg = data.inb[4 : 4 + msg_len]
                data.inb = data.inb[4 + msg_len :]  # remove processed bytes

                # Decode/parse JSON
                try:
                    request_obj = json.loads(raw_msg.decode("utf-8"))
                except json.JSONDecodeError as e:
                    response_obj = {
                        "status": "error",
                        "error": f"JSON parse error: {str(e)}"
                    }
                    self.queue_json_message(data, response_obj)
                    continue

                # Dispatch
                response_obj = self.handle_json_request(request_obj)
                # Send response
                self.queue_json_message(data, response_obj)

        # Handle writable socket
        if mask & selectors.EVENT_WRITE:
            if data.outb:
                try:
                    sent = tls_conn.send(data.outb)
                    data.outb = data.outb[sent:]
                except ssl.SSLWantWriteError:
                    return
                except ssl.SSLError as e:
                    self.logger.error("TLS write error: %s", e)
                    self.sel.unregister(tls_conn)
                    tls_conn.close()
                    return

    def queue_json_message(self, data, response_obj):
        """
        Encode the response_obj to JSON, prefix its length (4 bytes, big-endian),
        then append to data.outb for sending.
        """
        json_str = json.dumps(response_obj)
        encoded = json_str.encode("utf-8")
        length_prefix = len(encoded).to_bytes(4, "big")  # 4-byte length
        data.outb += length_prefix + encoded

    def handle_json_request(self, req):
        """
        Dispatch JSON request based on the 'action' field.
        """
        action = req.get("action", "").lower()
        if action == "register":
            username = req.get("from", "")
            password = req.get("password", "")
            return self.handle_register(username, password)

        elif action == "login":
            username = req.get("from", "")
            password = req.get("password", "")
            return self.handle_login(username, password)

        elif action == "message":
            session_id = req.get("session_id")
            from_user = req.get("from", "")
            to_user = req.get("to", "")
            message = req.get("message", "")
            return self.handle_message(session_id, from_user, to_user, message)

        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}"
            }

    def handle_register(self, username, password):
        """
        Handle the 'register' action by creating a new user in the database.
        """
        # 1) Check password length
        if len(password) >= 256:
            # Example JSON error message
            return {
                "status": "error",
                "error": "Password is too long"
            }

        # 2) Check if username already exists
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        row = c.fetchone()

        if row is not None:
            conn.close()
            return {
                "status": "error",
                "error": "Username already exists"
            }

        # 3) Hash the password
        hashed_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # 4) Insert into DB
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pass))
            conn.commit()
        except Exception as e:
            conn.close()
            return {
                "status": "error",
                "error": f"Database error: {str(e)}"
            }

        conn.close()
        return {
            "status": "ok",
            "message": "Registration successful"
        }

    def handle_login(self, username, password):
        """
        Handle the 'login' action by verifying user credentials
        and creating a new session.
        """
        # 1) Check if user exists
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            return {
                "status": "error",
                "error": "Invalid username or password"
            }

        stored_hashed_pass = row[0]
        # 2) Check the provided password against the stored hash
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_pass.encode('utf-8')):
            return {
                "status": "error",
                "error": "Invalid username or password"
            }

        # 3) If valid, create a session ID
        session_id = secrets.token_hex(16)
        self.active_sessions[session_id] = username
        self.logger.debug(f"Created session ID: {session_id} for user: {username}")

        return {
            "status": "ok",
            "session_id": session_id
        }

    def handle_message(self, session_id, from_user, to_user, msg):
        """
        Handle the 'message' action by verifying the session and user,
        then printing (or forwarding) the message.
        """
        # 1) Check session
        if not session_id or session_id not in self.active_sessions:
            self.logger.error(f"Invalid session: {session_id} from user: {from_user}")
            return {
                "status": "error",
                "error": "Invalid session"
            }

        # 2) Confirm that from_user matches this session
        if from_user != self.active_sessions[session_id]:
            return {
                "status": "error",
                "error": "Session does not match 'from' user"
            }

        # 3) "Send" the message (here, just print to server console)
        print(f"[MESSAGE] {from_user} -> {to_user}: {msg}")

        return {
            "status": "ok",
            "message": f"Message delivered to {to_user}"
        }

    def start(self):
        """
        Start the server loop, accepting incoming connections and servicing them.
        """
        self.setup_logging()
        self.logger.info("Starting the server...")
        self.logger.debug("About to call setup_database()")

        self.setup_database()

        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        # Create, bind, and listen on the socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
            lsock.bind((self.host, self.port))
            lsock.listen()
            self.logger.debug(f"Listening on {self.host}:{self.port}")
            lsock.setblocking(False)

            self.sel.register(lsock, selectors.EVENT_READ, data=None)

            try:
                while True:
                    events = self.sel.select(timeout=None)
                    for key, mask in events:
                        self.logger.debug(f"Selector event: {key}, mask={mask}")
                        if key.data is None:
                            # New incoming connection
                            self.accept_wrapper(key.fileobj, context)
                        else:
                            # Existing connection ready for I/O
                            self.service_connection(key, mask)
            except KeyboardInterrupt:
                self.logger.info("Caught keyboard interrupt, exiting")
            finally:
                self.sel.close()


if __name__ == "__main__":
    # Example usage:
    server = ChatServer(
        host=HOST,
        port=PORT,
        db_file=DB_FILE,
        cert_file="security/server.crt",
        key_file="security/server.key"
    )
    server.start()