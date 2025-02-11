from abc import ABC, abstractmethod
from typing import Tuple, Optional
import socket

class WireMessage(ABC):
    @classmethod
    @abstractmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        """
        Construct a wire message (as bytes) from the provided parameters.
        
        This method should encapsulate any encoding (e.g., JSON) and framing (e.g., length prefix)
        details.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def parse_wire_message(cls, wire_message: bytes) -> Tuple[str, str, str, str, str, str]:
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