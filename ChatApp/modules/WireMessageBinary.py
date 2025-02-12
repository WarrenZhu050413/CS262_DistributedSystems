import socket
from typing import Optional, Dict, Any
from ChatApp.modules.WireMessage import WireMessage

class WireMessageBinary(WireMessage):
    protocol_version: int = 1
    # Define the fixed order of fields (excluding protocol_version, which is sent as one byte)
    field_order = ["action", "from_user", "to_user", "password", "msg", "session_id"]

    @classmethod
    def encode_message(cls, message: dict) -> bytes:
        """
        Encodes a message dict into our custom binary format.
        
        Format:
            [4 bytes overall message length (big-endian) of the following message]
            [1 byte protocol_version]
            For each field in order ("action", "from_user", "to_user", "password", "msg", "session_id"):
                [4 bytes field length (big-endian)]
                [field payload as UTF-8 bytes]
        """
        out = bytearray()
        
        # Append protocol version (1 byte)
        try:
            out.append(cls.protocol_version)
        except Exception as e:
            raise ValueError(f"Protocol version needs to be between 0 and 255: {e}")

        # For each field, encode its value as UTF-8, prefix it with a 4-byte length, then add it.
        for field in cls.field_order:
            if field not in message:
                raise ValueError(f"Missing required field: {field}")
            value: str = message[field]
            field_bytes: bytes = value.encode("utf-8")
            # Append the length (4 bytes, big-endian)
            out.extend(len(field_bytes).to_bytes(4, "big"))
            # Append the actual field data
            out.extend(field_bytes)
        
        # Now prefix the entire message (protocol version + all fields) with its overall length.
        message_bytes = bytes(out)
        total_length = len(message_bytes)
        final_message = total_length.to_bytes(4, "big") + message_bytes
        return final_message

    @classmethod
    def make_wire_message(cls, action: str, from_user: str, to_user: str, password: str, msg: str, session_id: str) -> bytes:
        """
        Constructs a complete wire message using our custom binary protocol.
        """
        message_dict = {
            "action": action,
            "from_user": from_user,
            "to_user": to_user,
            "password": password,
            "msg": msg,
            "session_id": session_id
        }
        return cls.encode_message(message_dict)

    @classmethod
    def parse_wire_message(cls, wire_message: bytes) -> Dict[str, Any]:
        """
        Parses a wire message in our custom binary format into a Python dictionary.
        
        Expected format (assuming the overall length prefix has been stripped by read_wire_message):
            Byte 0: protocol version
            Then for each field in order ("action", "from_user", "to_user", "password", "msg", "session_id"):
                4 bytes: length (big-endian)
                'length' bytes: field payload (UTF-8 encoded)
        """
        data: Dict[str, Any] = {}
        offset = 0

        if len(wire_message) < 1:
            raise ValueError("Wire message too short: missing protocol version")
        # Read and store the protocol version
        data["protocol_version"] = wire_message[offset]
        offset += 1

        # Process each field in the defined order.
        for field in cls.field_order:
            if offset + 4 > len(wire_message):
                raise ValueError(f"Wire message too short: missing length for field '{field}'")
            field_length = int.from_bytes(wire_message[offset:offset+4], "big")
            offset += 4

            if offset + field_length > len(wire_message):
                raise ValueError(f"Wire message too short: missing data for field '{field}'")
            field_value = wire_message[offset: offset+field_length].decode("utf-8")
            offset += field_length
            data[field] = field_value

        return data

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """
        Reads exactly n bytes from the socket. (Delegates to the parent implementation.)
        """
        return WireMessage._recv_exactly(sock, n)

    @classmethod
    def read_wire_message(cls, sock: socket.socket) -> bytes:
        """
        Reads a complete wire message from the socket using our binary protocol.
        
        Steps:
          1. Read 4 bytes for the overall message length.
          2. Read that many bytes from the socket.
        Returns the complete message (excluding the overall length prefix).
        """
        # Read overall message length (4 bytes)
        length_data: bytes = cls._recv_exactly(sock, 4)
        if not length_data or len(length_data) != 4:
            raise ConnectionError("No overall message length received from server.")
        total_length = int.from_bytes(length_data, "big")
        # Read the complete message of total_length bytes.
        message_data = cls._recv_exactly(sock, total_length)
        if not message_data or len(message_data) != total_length:
            raise ConnectionError("Incomplete message received from server.")
        return message_data
