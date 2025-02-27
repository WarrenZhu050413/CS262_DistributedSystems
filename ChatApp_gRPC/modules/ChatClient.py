import threading
from typing import Dict, Any, Optional
import grpc
import csv

from ChatApp_gRPC.proto_generated import chat_pb2
from ChatApp_gRPC.proto_generated import chat_pb2_grpc


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


        if cafile:
            # Load the certificate file
            with open(cafile, 'rb') as f:
                root_cert = f.read()
            
            credentials = grpc.ssl_channel_credentials(
                root_certificates=root_cert,
                private_key=None,
                certificate_chain=None
            )
            
            # Create channel with the certificate and override the target name
            self.channel = grpc.secure_channel(
                f'{host}:{port}', 
                credentials,
                options=(
                    ('grpc.ssl_target_name_override', 'localhost'),
                    ('grpc.default_authority', 'localhost')
                )
            )
        else:
            self.channel = grpc.insecure_channel(f'{host}:{port}')
            
        self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
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
            Dict[str, Any]: The server's response as a dictionary containing:
            Dict[str, Any]: The server's response as a dictionary
        """

        if action == "register":
            request = chat_pb2.RegisterRequest(username=from_user, password=password)
            # Log request size
            request_size = len(request.SerializeToString())

            response = self.stub.Register(request)
            # Log response size
            response_size = len(response.SerializeToString())

            return {"status": response.status, "content": response.content}

        elif action == "login":
            request = chat_pb2.LoginRequest(username=from_user, password=password)
            # Log request size
            request_size = len(request.SerializeToString())

            response = self.stub.Login(request)
            # Log response size
            response_size = len(response.SerializeToString())

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
            # Log request size
            request_size = len(request.SerializeToString())
            response = self.stub.SendMessage(request)
            # Log response size
            response_size = len(response.SerializeToString())

            return {"status": response.status, "content": response.content, "error": response.error}

        elif action == "read_messages":
            request = chat_pb2.ReadMessagesRequest(
                session_id=self.session_id,
                from_user=from_user,
                count=int(msg)  # assuming msg is used to indicate the count
            )
            # Log request size
            request_size = len(request.SerializeToString())

            response = self.stub.ReadMessages(request)
            # Log response size
            response_size = len(response.SerializeToString())

            # Convert ChatMessage objects into dicts
            messages = [
                {"id": m.id, "from_user": m.from_user, "content": m.content}
                for m in response.messages
            ]
            return {"status": response.status, "messages": messages, "error": response.error}

        elif action == "list_accounts":
            request = chat_pb2.ListAccountsRequest(
                session_id=self.session_id,
                pattern=msg  # using msg as the search pattern
            )
            # Log request size
            request_size = len(request.SerializeToString())
            response = self.stub.ListAccounts(request)
            # Log response size
            response_size = len(response.SerializeToString())

            return {"status": response.status, "accounts": list(response.accounts), "error": response.error}

        elif action == "delete_messages":
            # In this case, we assume 'msg' is a comma-separated string of message IDs.
            message_ids = [int(mid) for mid in msg.split(',')]
            request = chat_pb2.DeleteMessagesRequest(
                session_id=self.session_id,
                from_user=from_user,
                message_ids=message_ids
            )
            # Log request size
            request_size = len(request.SerializeToString())
            response = self.stub.DeleteMessages(request)
            # Log response size
            response_size = len(response.SerializeToString())

            # Process messages similarly to read_messages.
            messages_list = [
                {"id": m.id, "from_user": m.from_user, "content": m.content}
                for m in response.messages
            ]
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
            # Log request size
            request_size = len(request.SerializeToString())
            response = self.stub.DeleteAccount(request)
            # Log response size
            response_size = len(response.SerializeToString())

            return {"status": response.status, "content": response.content, "error": response.error}

        else:
            raise ValueError("Unsupported action")

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
                    callback(chat_msg)
            except grpc.RpcError as e:
                # If the server disconnects or there's an error, handle it
                print("Listener thread ended:", e)
        
        self.listener_thread = threading.Thread(target=run_listen, daemon=True)
        self.listener_thread.start()

def log_to_csv(req_or_resp: str, data_size: int) -> None:
    """
    Logs relevant request/response data to a CSV file.

    Args:
        action (str): The action (e.g. "login", "register", "send_message", etc.)
        from_user (str): The username of the sender
        to_user (str): The username of the recipient
        req_or_resp (str): "request" or "response"
        data_size (int): The size of the data in bytes
    """
    with open("grpc_size.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            req_or_resp,
            data_size
        ])