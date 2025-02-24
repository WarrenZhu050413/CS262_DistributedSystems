# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import chat_pb2 as chat__pb2


class ChatServiceStub(object):
    """The gRPC service definition
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Register = channel.unary_unary(
                '/chat.ChatService/Register',
                request_serializer=chat__pb2.RegisterRequest.SerializeToString,
                response_deserializer=chat__pb2.RegisterResponse.FromString,
                )
        self.Login = channel.unary_unary(
                '/chat.ChatService/Login',
                request_serializer=chat__pb2.LoginRequest.SerializeToString,
                response_deserializer=chat__pb2.LoginResponse.FromString,
                )
        self.SendMessage = channel.unary_unary(
                '/chat.ChatService/SendMessage',
                request_serializer=chat__pb2.SendMessageRequest.SerializeToString,
                response_deserializer=chat__pb2.SendMessageResponse.FromString,
                )
        self.ReadMessages = channel.unary_unary(
                '/chat.ChatService/ReadMessages',
                request_serializer=chat__pb2.ReadMessagesRequest.SerializeToString,
                response_deserializer=chat__pb2.ReadMessagesResponse.FromString,
                )
        self.ListAccounts = channel.unary_unary(
                '/chat.ChatService/ListAccounts',
                request_serializer=chat__pb2.ListAccountsRequest.SerializeToString,
                response_deserializer=chat__pb2.ListAccountsResponse.FromString,
                )
        self.Listen = channel.unary_stream(
                '/chat.ChatService/Listen',
                request_serializer=chat__pb2.ListenRequest.SerializeToString,
                response_deserializer=chat__pb2.ListenResponse.FromString,
                )
        self.DeleteMessages = channel.unary_unary(
                '/chat.ChatService/DeleteMessages',
                request_serializer=chat__pb2.DeleteMessagesRequest.SerializeToString,
                response_deserializer=chat__pb2.DeleteMessagesResponse.FromString,
                )
        self.DeleteAccount = channel.unary_unary(
                '/chat.ChatService/DeleteAccount',
                request_serializer=chat__pb2.DeleteAccountRequest.SerializeToString,
                response_deserializer=chat__pb2.DeleteAccountResponse.FromString,
                )


class ChatServiceServicer(object):
    """The gRPC service definition
    """

    def Register(self, request, context):
        """--- Authentication ---
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Login(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendMessage(self, request, context):
        """--- Messaging ---
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ReadMessages(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ListAccounts(self, request, context):
        """--- Searching for accounts ---
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Listen(self, request, context):
        """--- Real-time message streaming ---
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteMessages(self, request, context):
        """--- Message/Account deletion ---
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteAccount(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_ChatServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'Register': grpc.unary_unary_rpc_method_handler(
                    servicer.Register,
                    request_deserializer=chat__pb2.RegisterRequest.FromString,
                    response_serializer=chat__pb2.RegisterResponse.SerializeToString,
            ),
            'Login': grpc.unary_unary_rpc_method_handler(
                    servicer.Login,
                    request_deserializer=chat__pb2.LoginRequest.FromString,
                    response_serializer=chat__pb2.LoginResponse.SerializeToString,
            ),
            'SendMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.SendMessage,
                    request_deserializer=chat__pb2.SendMessageRequest.FromString,
                    response_serializer=chat__pb2.SendMessageResponse.SerializeToString,
            ),
            'ReadMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.ReadMessages,
                    request_deserializer=chat__pb2.ReadMessagesRequest.FromString,
                    response_serializer=chat__pb2.ReadMessagesResponse.SerializeToString,
            ),
            'ListAccounts': grpc.unary_unary_rpc_method_handler(
                    servicer.ListAccounts,
                    request_deserializer=chat__pb2.ListAccountsRequest.FromString,
                    response_serializer=chat__pb2.ListAccountsResponse.SerializeToString,
            ),
            'Listen': grpc.unary_stream_rpc_method_handler(
                    servicer.Listen,
                    request_deserializer=chat__pb2.ListenRequest.FromString,
                    response_serializer=chat__pb2.ListenResponse.SerializeToString,
            ),
            'DeleteMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteMessages,
                    request_deserializer=chat__pb2.DeleteMessagesRequest.FromString,
                    response_serializer=chat__pb2.DeleteMessagesResponse.SerializeToString,
            ),
            'DeleteAccount': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteAccount,
                    request_deserializer=chat__pb2.DeleteAccountRequest.FromString,
                    response_serializer=chat__pb2.DeleteAccountResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'chat.ChatService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class ChatService(object):
    """The gRPC service definition
    """

    @staticmethod
    def Register(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/Register',
            chat__pb2.RegisterRequest.SerializeToString,
            chat__pb2.RegisterResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Login(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/Login',
            chat__pb2.LoginRequest.SerializeToString,
            chat__pb2.LoginResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SendMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/SendMessage',
            chat__pb2.SendMessageRequest.SerializeToString,
            chat__pb2.SendMessageResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ReadMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/ReadMessages',
            chat__pb2.ReadMessagesRequest.SerializeToString,
            chat__pb2.ReadMessagesResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ListAccounts(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/ListAccounts',
            chat__pb2.ListAccountsRequest.SerializeToString,
            chat__pb2.ListAccountsResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Listen(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/chat.ChatService/Listen',
            chat__pb2.ListenRequest.SerializeToString,
            chat__pb2.ListenResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeleteMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/DeleteMessages',
            chat__pb2.DeleteMessagesRequest.SerializeToString,
            chat__pb2.DeleteMessagesResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeleteAccount(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/chat.ChatService/DeleteAccount',
            chat__pb2.DeleteAccountRequest.SerializeToString,
            chat__pb2.DeleteAccountResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
