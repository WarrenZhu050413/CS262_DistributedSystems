import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage
import ast

c1='<'
c2='>'
c3='`'
c4='~'
c5='|'

class WireMessageBinary(WireMessage):
    # Use a protocol number distinct from the JSON protocol.
    protocol_version: int = 2
    # Define the replacement mapping (used during serialization).
    _REPLACEMENTS = {
        '{': c1, 
        '}': c2,
        '[': c3,
        ']': c4, 
        ',': c5, 
    }
    
    _REVERSE_REPLACEMENTS = {v: k for k, v in _REPLACEMENTS.items()}
    
    @classmethod
    def _custom_serialize(cls, message: dict) -> str:
        """
        Custom serializer that first converts the message dictionary to its
        Python literal string (via repr) and then replaces all instances of
        the structural characters with our rare ASCII control characters.
        """
        literal_str = repr(message)
        for char, replacement in cls._REPLACEMENTS.items():
            literal_str = literal_str.replace(char, replacement)
        return literal_str

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Converts the message dict to a string via our custom serializer,
        encodes it as UTF-8, and prefixes it with its 4-byte length.
        """
        payload_str = cls._custom_serialize(message)
        payload_bytes = payload_str.encode("utf-8")
        prefix = len(payload_bytes).to_bytes(4, "big")
        return prefix + payload_bytes

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str,
                          password: str, msg: str, session_id: str) -> bytes:
        """
        Constructs a complete wire message.
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
        Parses the custom wire message (after removing the 4-byte length prefix)
        back into a dictionary. This is done by decoding the payload as a UTF-8 string,
        reversing the custom character substitutions, and then using ast.literal_eval
        to reconstruct the original dictionary. This mechanism supports nested lists
        (or dictionaries) as values.
        """
        try:
            payload_str = wire_message.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("Unable to decode message payload as UTF-8: " + str(e))
        data = cls._custom_deserialize(payload_str)
        return data
    
    @classmethod
    def _custom_deserialize(cls, payload_str: str) -> dict:
        """
        Reverses the custom serialization by undoing the character replacements,
        then uses ast.literal_eval to turn the resulting string back into a dictionary.
        """
        # Reverse the replacement: restore the original structural characters.
        for replacement, char in cls._REVERSE_REPLACEMENTS.items():
            payload_str = payload_str.replace(replacement, char)
        try:
            data = ast.literal_eval(payload_str)
        except Exception as e:
            raise ValueError("Failed to parse wire message: " + str(e))
        return data
