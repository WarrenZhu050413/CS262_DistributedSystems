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
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_ChatServiceServicer_to_server(ChatServiceServicer(host=HOST, port=PORT, db_file=DB_FILE, cert_file=CERT_FILE, key_file=KEY_FILE, log_file=LOG_FILE), server)
    server.add_insecure_port(f'{HOST}:{PORT}')
    server.start()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("Server stopping...")
        server.stop(grace=None)  # or some grace period in seconds

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()