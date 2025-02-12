import socket
from typing import Optional, Dict, Any
from .WireMessage import WireMessage

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
        '{': c1,  # File Separator (FS)
        '}': c2,  # Group Separator (GS)
        '[': c3,  # Record Separator (RS)
        ']': c4,  # Unit Separator (US)
        ',': c5,  # Escape (ESC) -- used here for commas
    }
    # (The reverse mapping is no longer needed since we parse the control characters directly.)
    
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
    def _custom_deserialize(cls, payload_str: str) -> dict:
        """
        Custom deserializer that directly parses our protocol format without
        reverting the control characters back to normal punctuation.
        
        We expect payload_str to have the following format:
        
            FS  <key-value pair> [ESC <key-value pair> ...] GS
        
        where:
          - Within each key–value pair, the key and value (both Python string
            literals) are separated by a colon (:).
          - Others are separated by c1-c5
        
        Note: This implementation assumes that keys and values are valid Python
        string literals (e.g. "'some text'" or "\"other text\"") and that colons
        do not appear unescaped inside the strings.
        """
        # Ensure the string starts and ends with the proper markers.
        print(payload_str)
        if not (payload_str.startswith(c1) and payload_str.endswith(c2)):
            raise ValueError("Invalid message format: missing dictionary markers")
        inner = payload_str[1:-1]  # Remove FS and GS
        print(inner)
        if not inner:
            return {}

        # Split the inner string on our custom comma marker (ESC)
        pairs = inner.split(c5)
        print(pairs)

        # # Helper: Check if a quote at position i is escaped.
        def is_escaped(s: str, i: int) -> bool:
            backslash_count = 0
            j = i - 1
            while j >= 0 and s[j] == '\\':
                backslash_count += 1
                j -= 1
            return (backslash_count % 2) == 1

        # Helper: Parse a Python string literal (e.g. "'text'" or "\"text\"")
        def parse_python_string(s: Any) -> str:
            if isinstance(s, int):
                s = str(s)
            # if len(s) < 2 or s[0] != s[-1] or s[0] not in ("'", '"'):
                # print(s[0])
                # print(s[-1])
                # raise ValueError("Invalid string literal: " + s)
            inner_str = s[1:-1]
            # Decode escape sequences (like \n, \t, \\, etc.)
            return bytes(inner_str, "utf-8").decode("unicode_escape")

        result = {}
        # Process each key-value pair.
        for pair in pairs:
            pair = pair.strip()
            print(pair)
            if not pair:
                continue

            # Find the colon (:) that separates key and value, ignoring colons inside quotes.
            sep_index = None
            in_quote = False
            current_quote = None
            for i, char in enumerate(pair):
                if char in ("'", '"'):
                    if not in_quote:
                        in_quote = True
                        current_quote = char
                    elif char == current_quote and not is_escaped(pair, i):
                        in_quote = False
                        current_quote = None
                elif char == ':' and not in_quote:
                    sep_index = i
                    break
            if sep_index is None:
                raise ValueError("Invalid key-value pair, missing colon: " + pair)
            
            key_literal = pair[:sep_index].strip()
            value_literal = pair[sep_index+1:].strip()
            print(key_literal)
            print(value_literal)
            key = parse_python_string(key_literal)
            print("Key successful")
            value = parse_python_string(value_literal)
            print("value successful")
            result[key] = value

        return result

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
        back into a dictionary.
        """
        try:
            payload_str = wire_message.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("Unable to decode message payload as UTF-8: " + str(e))
        return cls._custom_deserialize(payload_str)