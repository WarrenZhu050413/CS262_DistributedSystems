import unittest
import threading
import time
import os
import random
import string
import socket
import ssl
import selectors
import json

from ..modules.ChatClient import ChatClient
from ..modules.ChatServer import ChatServer
from ..modules.config import HOST, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE, SUPPORTED_ACTIONS
from ..modules.WireMessageJSON import WireMessageJSON

###############################################################################
# Parent Test Class with shared setUpClass, setUp, and tearDown methods
###############################################################################
class WireProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Instead of using a fixed port, choose a free port for the tests.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, 0))
            cls.port = s.getsockname()[1]
        print(f"Using test port: {cls.port}")

    def setUp(self):
        # Remove any leftover database file
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

        # Initialize and start the chat server in a background thread.
        self.server = ChatServer(
            host=HOST,
            port=self.__class__.port,
            db_file=DB_FILE,
            cert_file=CERT_FILE,
            key_file=KEY_FILE,
            log_file=LOG_FILE
        )
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        # Allow time for the server to fully initialize.
        time.sleep(1.5)

    def tearDown(self):
        # Stop the server gracefully.
        try:
            self.server.stop()
        except Exception as e:
            print(f"Error stopping server: {e}")

        # Wait for the server thread to finish and allow the OS to free the port.
        self.server_thread.join(timeout=5)
        time.sleep(0.5)

        # Remove the database file.
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
            except Exception as e:
                print(f"Error removing DB file: {e}")
