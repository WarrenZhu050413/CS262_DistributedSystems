from abc import ABC, abstractmethod
from typing import Tuple, Optional
import socket

class WireMessage(ABC):
    """
    Abstract base class defining the wire protocol interface for network message handling.
    
    This class provides the contract for encoding, decoding, and transmitting messages
    over a network connection. Implementations must define the specific wire format
    and framing protocol.

    Provides a well-defined interface for encoding and decoding messages.

    Methods:
        make_wire_message(action, from_user, to_user, password, msg, session_id) -> bytes:
            Creates a formatted wire message from the given parameters.
            
        parse_wire_message(wire_message: bytes) -> Dict[str, Any]:
            Decodes a wire message into its component parts:
            (action, from_user, to_user, password, msg, session_id)
            
        read_wire_message(sock: socket.socket) -> bytes:
            Reads a complete message from a socket connection.
            
        _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
            Utility method to read exactly n bytes from a socket.

    API:
    make_wire_message() encodes a message into a bytestring, taking in inputs as separate fields.
    encode_message() encodes a dictionary into a bytestring.
    read_wire_message() reads a wire message from a socket.
    parse_wire_message() decodes a wire message into a dictionary.

    Usage:
    # Use make_wire_message() to encode a message into a bytestring
    wire_message = WireMessage.make_wire_message(action, from_user, to_user, password, msg, session_id)

    # Use encode_message() to encode a dictionary into a bytestring
    message = {
        "action": action,
        "from_user": from_user,
        "to_user": to_user,
        "password": password,
        "msg": msg,
        "session_id": session_id
    }

    wire_message = WireMessage.encode_message(message)

    # Use read_wire_message() to read a wire message from a socket
    wire_message = WireMessage.read_wire_message(sock)

    # Use parse_wire_message() to decode a wire message into a dictionary
    message = WireMessage.parse_wire_message(wire_message)

    Implementation Notes:
        - All string data should be properly encoded/decoded for wire transmission
        - Messages should include appropriate framing (e.g., length prefixes)
        - Socket operations should handle partial reads and connection failures
        - Implementations should validate message format and content
    """

    @classmethod
    @abstractmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        """
        Construct a wire message (as bytes) from the provided parameters.
        
        This method should encapsulate any encoding and framing (e.g., length prefix)
        details.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Encode a dictionary into a wire message (as bytes).
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def parse_wire_message(cls, wire_message: bytes) -> dict[str, Any]:
        """
        Parse the given wire message (bytes) and return a tuple:
        (action, from_user, to_user, password, msg).
        
        This method should handle any decoding and unframing of the wire message.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def read_wire_message(cls, sock: socket.socket) -> bytes:
        """
        Read the response from the server.
        """
        raise NotImplementedError

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Read exactly n bytes from the socket.
        Returns the bytes or None if the connection closes prematurely.
        """
        buf: bytes = b""
        while len(buf) < n:
            chunk: bytes = sock.recv(n - len(buf))
            if not chunk:
                return None # Returns None if the connection closes prematurely
            buf += chunk
        return buf