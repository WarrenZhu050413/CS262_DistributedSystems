import ast
import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage

class WireMessageBinary(WireMessage):
    # Use a protocol number distinct from the JSON protocol.
    protocol_version: int = 2

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Mimics the JSON protocol by converting the message dict to a string,
        encoding it in UTF-8, and prefixing it with its 4-byte length.
        
        (Instead of json.dumps, we use repr() so that we can later recover
         the original dictionary via ast.literal_eval.)
        """
        # Convert the dictionary to its Python literal string.
        payload_str = repr(message)
        payload_bytes = payload_str.encode("utf-8")
        # Prefix with a 4-byte big-endian length.
        prefix = len(payload_bytes).to_bytes(4, "big")
        return prefix + payload_bytes

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str,
                          password: str, msg: str, session_id: str) -> bytes:
        """
        Constructs a complete wire message. Note that the key for the message
        is "message" (not "msg") to exactly mimic the JSON protocol.
        """
        message_dict = {
            "protocol_version": cls.protocol_version,
            "action": action,
            "from_user": from_user,
            "to_user": to_user,
            "password": password,
            "message": msg,
            "session_id": session_id
        }
        return cls.encode_message(message_dict)

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Reads exactly n bytes from the socket. Delegates to the parent implementation.
        """
        return WireMessage._recv_exactly(sock, n)

    @classmethod
    def read_wire_message(cls, sock: socket.socket) -> bytes:
        """
        Reads the complete wire message from the socket.
        
        Steps:
          1. Read 4 bytes to determine the length.
          2. Read that many bytes.
        Returns the complete payload (excluding the 4-byte length prefix).
        """
        length_data: bytes = cls._recv_exactly(sock, 4)
        if not length_data or len(length_data) != 4:
            raise ConnectionError("No response length received from server.")
        total_length = int.from_bytes(length_data, "big")
        payload = cls._recv_exactly(sock, total_length)
        if not payload or len(payload) != total_length:
            raise ConnectionError("Server closed connection before sending a full response.")
        return payload

    @classmethod
    def parse_wire_message(cls, wire_message: bytes) -> Dict[str, Any]:
        """
        Parses the binary wire message (after removing the 4-byte length prefix)
        back into a dictionary. It does so by decoding the payload as a UTF-8 string
        and then using ast.literal_eval to reconstruct the dictionary.
        """
        try:
            payload_str = wire_message.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("Unable to decode message payload as UTF-8: " + str(e))
        try:
            # Convert the literal string back into a Python dictionary.
            data = ast.literal_eval(payload_str)
        except Exception as e:
            raise ValueError("Failed to parse wire message: " + str(e))
        return data
