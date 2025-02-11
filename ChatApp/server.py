#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .modules.ChatServer import ChatServer
from .modules.config import HOST, PORT, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE

if __name__ == "__main__":
    # Example usage:
    server = ChatServer(
        host=HOST,
        port=PORT,
        db_file=DB_FILE,
        cert_file=CERT_FILE,
        key_file=KEY_FILE,
        log_file=LOG_FILE
    )
    server.start()