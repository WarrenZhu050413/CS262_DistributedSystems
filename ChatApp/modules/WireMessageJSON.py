import json
import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage

import csv
import os
import time  # for high-resolution timing

class WireMessageJSON(WireMessage):
    protocol_version: int = 1

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Helper method to encode any JSON object as a length-prefixed message.
        Measures the time taken for encoding and logs it.
        """
        start_time = time.perf_counter()
        payload = json.dumps(message).encode("utf-8")
        prefix = len(payload).to_bytes(4, "big")
        result = prefix + payload
        elapsed = time.perf_counter() - start_time
        cls._log_operation_time("encode", elapsed)
        return result

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        message_json = {
            "protocol_version": cls.protocol_version,
            "action": action,
            "from_user": from_user,
            "to_user": to_user,
            "password": password,
            "message": msg,
            "session_id": session_id
        }
        return cls.encode_message(message_json)

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        return WireMessage._recv_exactly(sock, n)

    @classmethod
    def parse_wire_message(cls, wire_message: bytes) -> Dict[str, Any]:
        """
        Parses the JSON wire message (after removing the 4-byte length prefix)
        back into a dictionary. Measures the time taken and logs it.
        """
        start_time = time.perf_counter()
        try:
            data = json.loads(wire_message.decode('utf-8'))
        except Exception as e:
            raise ValueError("Error while parsing JSON wire message: " + str(e))
        elapsed = time.perf_counter() - start_time
        return data

    @classmethod
    def read_wire_message(cls, sock: socket.socket) -> bytes:
        """
        Read the response from the server.
        """
        # Read the response length prefix (4 bytes)
        length_data: bytes = cls._recv_exactly(sock, 4)
        if not length_data:
            raise ConnectionError("No response length received from server.")

        resp_length: int = int.from_bytes(length_data, 'big')
        # Read exactly resp_length bytes for the JSON response
        resp_bytes: bytes = cls._recv_exactly(sock, resp_length)
        if not resp_bytes:
            raise ConnectionError("Server closed connection before sending a full response.")

        return resp_bytes
    
    @classmethod
    def _log_operation_time(cls, operation: str, elapsed: float):
        """
        Appends a line to "json_efficiency.csv" with the protocol version,
        the operation type ("encode" or "parse"), and the elapsed time in seconds.
        If the file does not exist, a header is written first.
        """
        file_exists = os.path.isfile('json_efficiency.csv')
        with open('json_efficiency.csv', 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(['Protocol_Version', 'Operation', 'Elapsed_Time'])
            writer.writerow([cls.protocol_version, operation, elapsed])
