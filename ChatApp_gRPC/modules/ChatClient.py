import socket
import ssl
import threading  # REAL-TIME MOD: Needed for the listener thread
from typing import Dict, Any, Optional
from .WireMessageBinary import WireMessageBinary
import grpc
import chat_pb2
import chat_pb2_grpc

class ChatClient:
    """
    A client for connecting to and communicating with the chat server.
    
    Handles sending requests, managing sessions, and maintaining a persistent 
    connection for real-time message delivery.
    """

    def __init__(self, host: str, port: int, cafile: str) -> None:
        """
        Initialize a new ChatClient instance.

        Args:
            host (str): The hostname of the chat server
            port (int): The port number the server is listening on
            cafile (str): Path to the SSL certificate authority file
        """
        self.host: str = host
        self.port: int = port
        self.session_id: Optional[str] = None  # Keep session state here if needed

        # Create and configure the SSL context
        self.context: ssl.SSLContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(cafile=cafile)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        # Create a channel to the gRPC server.
        channel = grpc.insecure_channel(f"{self.host}:{self.port}")
        self.stub = chat_pb2_grpc.ChatServiceStub(channel)

        # NEW: Attributes to manage the persistent listener.
        self.listener_thread = None
        self.listener_socket = None

    def send_request(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        """
        Send a request to the chat server and return the response.

        Args:
            action (str): The type of request (e.g. "login", "send_message")
            from_user (str): The username of the sender
            to_user (str): The username of the recipient
            password (str): The user's password (for authentication)
            msg (str): The message content

        Returns:
            Dict[str, Any]: The server's response as a dictionary
        """

        if action == "register":
            request = chat_pb2.RegisterRequest(username=from_user, password=password)
            response = self.stub.Register(request)
            return {"status": response.status, "content": response.content}

        elif action == "login":
            request = chat_pb2.LoginRequest(username=from_user, password=password)
            response = self.stub.Login(request)
            # Save session_id if provided
            if response.session_id:
                self.session_id = response.session_id
            return {
                "status": response.status,
                "session_id": response.session_id,
                "unread_messages": response.unread_messages,
                "error": response.error
            }

        elif action == "send_message":
            request = chat_pb2.SendMessageRequest(
                session_id=self.session_id,
                from_user=from_user,
                to_user=to_user,
                content=msg
            )
            response = self.stub.SendMessage(request)
            return {"status": response.status, "content": response.content, "error": response.error}

        elif action == "read_messages":
            request = chat_pb2.ReadMessagesRequest(
                session_id=self.session_id,
                from_user=from_user,
                count=int(msg)  # TODO: assuming msg is used to indicate the count
            )
            response = self.stub.ReadMessages(request)
            # You might want to convert the list of ChatMessage objects into dicts
            messages = [{"id": m.id, "from_user": m.from_user, "content": m.content} for m in response.messages]
            return {"status": response.status, "messages": messages, "error": response.error}

        elif action == "list_accounts":
            request = chat_pb2.ListAccountsRequest(
                session_id=self.session_id,
                pattern=msg  # using msg as the search pattern
            )
            response = self.stub.ListAccounts(request)
            # TODO: parse this list like read_messages?
            return {"status": response.status, "accounts": list(response.accounts), "error": response.error}

        elif action == "delete_messages":
            # In this case, you may need to adjust how you pass multiple message IDs.
            # Here, we assume 'msg' is a comma-separated string of message IDs.
            message_ids = [int(mid) for mid in msg.split(',')]
            request = chat_pb2.DeleteMessagesRequest(
                session_id=self.session_id,
                from_user=from_user,
                message_ids=message_ids
            )
            response = self.stub.DeleteMessages(request)
            # Process messages similarly to read_messages.
            messages_list = [{"id": m.id, "from_user": m.from_user, "content": m.content} for m in response.messages]
            return {
                "status": response.status,
                "content": response.content,
                "messages": messages_list,
                "error": response.error
            }

        elif action == "delete_account":
            request = chat_pb2.DeleteAccountRequest(
                session_id=self.session_id,
                username=from_user
            )
            response = self.stub.DeleteAccount(request)
            return {"status": response.status, "content": response.content, "error": response.error}

        else:
            raise ValueError("Unsupported action")

            
    # def delete_account(self, username):
    #     """
    #     Send a request to delete a user account.

    #     Args:
    #         username (str): The username of the account to delete

    #     Returns:
    #         Dict[str, Any]: The server's response as a dictionary
    #     """
    #     wire_message = WireMessageBinary.make_wire_message(
    #         action="delete_account",
    #         from_user=username,
    #         to_user="",  # not used for deletion
    #         password="",  # not needed here
    #         msg="",
    #         session_id=self.session_id
    #     )

    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
    #         raw_socket.connect((self.host, self.port))
    #         with self.context.wrap_socket(raw_socket, server_side=False, server_hostname=self.host) as s:
    #             s.sendall(wire_message)
    #             resp_bytes: bytes = WireMessageBinary.read_wire_message(s)
    #             resp_dict: Dict[str, Any] = WireMessageBinary.parse_wire_message(resp_bytes)
    #             return resp_dict

    # ------------------------------
    # NEW: Persistent listener for real-time messages
    # ------------------------------
    def start_listener(self, username, session_id, callback):
        """
        Spawns a background thread which calls the server-streaming RPC Listen()
        and fires 'callback(message)' whenever a new ChatMessage arrives.
        """
        def run_listen():
            request = chat_pb2.ListenRequest(
                username=username,
                session_id=session_id
            )
            try:
                for chat_msg in self.stub.Listen(request):
                    # 'chat_msg' is a ChatMessage from the server
                    # Call the callback with the new message
                    callback(chat_msg)
            except grpc.RpcError as e:
                # If the server disconnects or there's an error, handle it
                print("Listener thread ended:", e)
        
        self.listener_thread = threading.Thread(target=run_listen, daemon=True)
        self.listener_thread.start()

    # def stop_listener(self):
    #     """
    #     Stop the background listener thread and close its connection.
    #     """
    #     if self.listener_socket is not None:
    #         self.listener_socket.close()
    #         self.listener_socket = None
