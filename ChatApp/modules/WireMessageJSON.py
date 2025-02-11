import json
import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage

class WireMessageJSON(WireMessage):
    protocol_version: int = 1

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Helper method to encode any JSON object as a length-prefixed message.
        """
        payload = json.dumps(message).encode("utf-8")
        prefix = len(payload).to_bytes(4, "big")
        return prefix + payload

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        message_json = {
            "protocol_version": cls.protocol_version,
            "action": action,
            "from_user": from_user,
            "to_user": to_user,
            "password": password,
            "msg": msg,
            "session_id": session_id
        }
        return cls.encode_message(message_json)

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        return WireMessage._recv_exactly(sock, n)

    @staticmethod
    def parse_wire_message(wire_message: bytes) -> Dict[str, Any]:
        data = json.loads(wire_message.decode('utf-8'))
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
    