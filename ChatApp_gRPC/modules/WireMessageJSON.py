import json
import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage

class WireMessageJSON(WireMessage):
    """
    JSON implementation of the WireMessage protocol.
    
    This class handles encoding and decoding of messages using JSON serialization,
    with length-prefixed framing for socket transmission.
    
    Attributes:
        protocol_version (int): Version identifier for this protocol implementation (1 for JSON)
    """
    protocol_version: int = 1

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Encode a dictionary as a length-prefixed JSON message.

        Args:
            message (dict): Dictionary to encode

        Returns:
            bytes: Length-prefixed JSON message as bytes, with 4-byte length prefix
                  followed by UTF-8 encoded JSON payload
        """
        payload = json.dumps(message).encode("utf-8")
        prefix = len(payload).to_bytes(4, "big")
        return prefix + payload

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        """
        Construct a complete wire message from the given parameters.

        Args:
            action (str): Action type for this message
            from_user (str): Username of sender
            to_user (str): Username of recipient
            password (str): Password for authentication
            msg (str): Message content
            session_id (str): Session identifier

        Returns:
            bytes: Encoded wire message with length prefix and JSON payload
        """
        message_json = {
            "protocol_version": cls.protocol_version,
            "action": action,
            "from_user": from_user,          # "from_user"
            "to_user": to_user,              # "to_user"
            "password": password,
            "message": msg,             # use "message" instead of "msg"
            "session_id": session_id
        }
        return cls.encode_message(message_json)

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Read exactly n bytes from a socket.

        Args:
            sock (socket.socket): Socket to read from
            n (int): Number of bytes to read

        Returns:
            Optional[bytes]: The bytes read, or None if connection closed prematurely
        """
        return WireMessage._recv_exactly(sock, n)

    @staticmethod
    def parse_wire_message(wire_message: bytes) -> Dict[str, Any]:
        """
        Parse a wire message from bytes into a dictionary.

        Args:
            wire_message (bytes): The wire message to parse

        Returns:
            Dict[str, Any]: Parsed message as a dictionary
        """
        data = json.loads(wire_message.decode('utf-8'))
        return data

    @classmethod
    def read_wire_message(cls, sock: socket.socket) -> bytes:
        """
        Read a complete wire message from a socket.

        Reads the 4-byte length prefix followed by the JSON payload.

        Args:
            sock (socket.socket): Socket to read from

        Returns:
            bytes: Complete wire message

        Raises:
            ConnectionError: If connection closes before complete message is read
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