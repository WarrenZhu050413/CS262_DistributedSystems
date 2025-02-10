
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

sel = selectors.DefaultSelector()
logger = logging.getLogger(__name__)

# In-memory session storage:
# session_id (str) -> username (str)
active_sessions = {}

def setup_database():
    """
    Create a 'users' table in SQLite if it doesn't exist.
    Columns: username TEXT PRIMARY KEY, password TEXT (hashed password).
    """
    logger.debug("Setting up database...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

def accept_wrapper(sock, context):
    conn, addr = sock.accept()
    logger.debug(f"Accepted connection from {addr}")
    try:
        tls_conn = context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
    except ssl.SSLError as e:
        logger.error("TLS handshake failed:", e)
        conn.close()
        return

    tls_conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, 
                                 inb=b"", 
                                 outb=b"", 
                                 handshake_complete=False
                                 )

    sel.register(tls_conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)

def service_connection(key, mask):
    tls_conn = key.fileobj
    data = key.data

    # 1) If the handshake hasn't completed, try to do it.
    if not data.handshake_complete:
        try:
            tls_conn.do_handshake()
            data.handshake_complete = True  # success!
            logger.debug(f"Handshake complete for {data.addr}")
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # We need more reads, so return and wait for next EVENT_READ
            return
        except (OSError, ssl.SSLError) as e:
            # Hard error, close
            logger.error("TLS handshake failed:", e)
            sel.unregister(tls_conn)
            tls_conn.close()
            return

    # Handle readable socket
    if mask & selectors.EVENT_READ:
        try:
            recv_data = tls_conn.recv(4096)  # read up to 4KB
        except ssl.SSLWantReadError:
            return
        except ssl.SSLError as e:
            logger.error("TLS handshake failed:", e)
            sel.unregister(tls_conn)
            tls_conn.close()
            return
        except ConnectionResetError:
            recv_data = None

        if recv_data:
            data.inb += recv_data
        else:
            logger.debug(f"Closing connection to {data.addr}")
            sel.unregister(tls_conn)
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
                queue_json_message(data, response_obj)
                continue

            # Dispatch
            response_obj = handle_json_request(request_obj)
            # Send response
            queue_json_message(data, response_obj)

    # Handle writable socket
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            try:
                sent = tls_conn.send(data.outb)
                data.outb = data.outb[sent:]
            except ssl.SSLWantWriteError:
                return
            except ssl.SSLError as e:
                logger.error("TLS handshake failed:", e)
                sel.unregister(tls_conn)
                tls_conn.close()
                return

def queue_json_message(data, response_obj):
    """
    Encode the response_obj to JSON, prefix its length (4 bytes, big-endian),
    then append to data.outb for sending.
    """
    json_str = json.dumps(response_obj)
    encoded = json_str.encode("utf-8")
    length_prefix = len(encoded).to_bytes(4, "big")  # 4-byte length
    data.outb += length_prefix + encoded

def handle_json_request(req):
    """
    Dispatch JSON request based on 'action' field.
    """
    action = req.get("action", "").lower()
    if action == "register":
        username = req.get("from", "")
        password = req.get("password", "")
        return handle_register(username, password)

    elif action == "login":
        username = req.get("from", "")
        password = req.get("password", "")
        return handle_login(username, password)

    elif action == "message":
        session_id = req.get("session_id")
        from_user = req.get("from", "")
        to_user = req.get("to", "")
        message = req.get("message", "")
        return handle_message(session_id, from_user, to_user, message)

    else:
        return {
            "status": "error",
            "error": f"Unknown action: {action}"
        }

def handle_register(username, password):
    # 1) Check password length
    if len(password) >= 256:
        # Example JSON error message
        return {
            "status": "error",
            "error": "Password is too long"
        }

    # 2) Check if username already exists
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row is not None:
        conn.close()
        # Example JSON error message
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

def handle_login(username, password):
    # 1) Check if user exists
    conn = sqlite3.connect(DB_FILE)
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
    # 2) Hash the given password, compare
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_pass.encode('utf-8')):
        return {"status": "error",
                "error": "Invalid username or password"
            }

    # 3) If valid, create a session ID
    session_id = secrets.token_hex(16)
    active_sessions[session_id] = username
    logger.debug(f"Created session ID: {session_id} for user: {username}")

    return {
        "status": "ok",
        "session_id": session_id
    }

def handle_message(session_id, from_user, to_user, msg):
    # 1) Check session
    if not session_id or session_id not in active_sessions:
        logger.error(f"Invalid session: {session_id} from user: {from_user}")
        return {
            "status": "error",
            "error": "Invalid session"
        }

    # 2) Optionally confirm that from_user matches this session
    if from_user != active_sessions[session_id]:
        return {
            "status": "error",
            "error": "Session does not match 'from' user"
        }

    # 3) "Send" (or just echo) the message; in a real app you might store/forward it.
    print(f"[MESSAGE] {from_user} -> {to_user}: {msg}")

    return {
        "status": "ok",
        "message": f"Message delivered to {to_user}"
    }

def main():

    # Configure logging here. For example:
    logging.basicConfig(
        level=logging.DEBUG,             # or logging.INFO in production
        filename="./logging/server.log",
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )
    
    logger.info("Starting the server...")
    
    # If you want to see a debug message:
    logger.debug("Debugging details: about to call setup_database()")

    setup_database()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
        lsock.bind((HOST, PORT))
        lsock.listen()
        logger.debug(f"Listening on {HOST}:{PORT}")
        lsock.setblocking(False)
        sel.register(lsock, selectors.EVENT_READ, data=None)

        try:
            while True:
                events = sel.select(timeout=None)
                for key, mask in events:
                    logger.debug(f"Selector event: {key}, mask={mask}")
                    if key.data is None:
                        accept_wrapper(key.fileobj, context)
                    else:
                        service_connection(key, mask)
        except KeyboardInterrupt:
            logger.info("Caught keyboard interrupt, exiting")
        finally:
            sel.close()

if __name__ == "__main__":
    main()
