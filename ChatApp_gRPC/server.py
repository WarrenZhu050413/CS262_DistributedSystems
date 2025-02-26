#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ChatApp_gRPC.modules.ChatServer import ChatServiceServicer
from ChatApp_gRPC.modules.config import HOST, PORT, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE
import logging
import grpc
from concurrent import futures
import secrets
import sqlite3
import bcrypt
import ssl
import queue
import logging
from ChatApp_gRPC.proto_generated import chat_pb2
from ChatApp_gRPC.proto_generated import chat_pb2_grpc
from ChatApp_gRPC.proto_generated.chat_pb2_grpc import add_ChatServiceServicer_to_server

def serve():
    # Load SSL credentials
    with open(CERT_FILE, 'rb') as f:
        cert_data = f.read()
    with open(KEY_FILE, 'rb') as f:
        private_key = f.read()

    # Create SSL credentials
    server_credentials = grpc.ssl_server_credentials(
        [(private_key, cert_data)]
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_ChatServiceServicer_to_server(ChatServiceServicer(host=HOST, port=PORT, db_file=DB_FILE, cert_file=CERT_FILE, key_file=KEY_FILE, log_file=LOG_FILE), server)
    # Replace insecure port with secure port
    server.add_secure_port(f'{HOST}:{PORT}', server_credentials)
    server.start()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("Server stopping...")
        server.stop(grace=None)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()