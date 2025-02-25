# ChatApp documentation

## Table of Contents

- [ChatApp documentation](#chatapp-documentation)
	- [Table of Contents](#table-of-contents)
- [1. Introduction](#1-introduction)
- [2. Features](#2-features)
- [3. Architecture](#3-architecture)
- [4. Package Structure](#4-package-structure)
- [5. Core Components](#5-core-components)
	- [ChatClient](#chatclient)
	- [ChatClientApp](#chatclientapp)
	- [ChatServer](#chatserver)
- [6. Supported gRPC Methods](#6-supported-grpc-methods)
		- [Register](#register)
		- [Login](#login)
		- [SendMessage](#sendmessage)
		- [ReadMessages](#readmessages)
		- [ListAccounts](#listaccounts)
		- [DeleteMessages](#deletemessages)
		- [DeleteAccount](#deleteaccount)
		- [Listen (streaming)](#listen-streaming)
- [7. Security \& TLS](#7-security--tls)
- [8. Data Persistence](#8-data-persistence)
- [9. Real-Time Message Delivery](#9-real-time-message-delivery)
- [10. Design Principles](#10-design-principles)
- [11. Quick Start Guide](#11-quick-start-guide)
	- [Prerequisites](#prerequisites)
	- [Installation](#installation)
	- [Running the Server](#running-the-server)
	- [Running the Client](#running-the-client)
- [12. Testing](#12-testing)
- [13. Logging](#13-logging)
- [14. Extensibility](#14-extensibility)
- [15. Code Reference](#15-code-reference)
	- [proto/chat.proto](#protochatproto)
	- [modules/chat\_pb2.py and modules/chat\_pb2\_grpc.py](#moduleschat_pb2py-and-moduleschat_pb2_grpcpy)
	- [modules/chatclient.py](#moduleschatclientpy)
	- [modules/chatclientapp.py](#moduleschatclientapppy)
	- [modules/chatserver.py](#moduleschatserverpy)

---

# 1. Introduction

ChatApp is a modular chat application that uses gRPC for client-server communication. It demonstrates a clean separation of concerns, where each layer (UI, network, business logic) is clearly delimited to make the system robust, secure, and extensible.

**Key aspects of the system include:**

- A gRPC-based server handling authentication, messaging, and user account management.
- A Python client that calls the server stubs generated from `chat.proto`.
- A Tkinter GUI (`ChatClientApp`) for interactive use.
- SQLite-backed storage and optional real-time streaming of new messages.

---

# 2. Features

- **gRPC Communication**: All requests (Register, Login, SendMessage, etc.) use gRPC calls, with streaming support for real-time message delivery.
- **Built-in TLS**: gRPC manages TLS (encryption in transit) on both the client and server sides.
- **User Account Management**: Create, list, authenticate, and delete user accounts.
- **Messaging**: Send messages, retrieve unread messages, and optionally receive real-time message streams.
- **Database Persistence**: Uses SQLite for user credentials and message storage (with bcrypt for password hashing).

---

# 3. Architecture

ChatApp follows a client-server model using gRPC:

- **Server**: Implements the `ChatService` (as defined in `chat.proto`), listens for incoming gRPC requests, manages a database of user accounts, and handles real-time streaming for message delivery.
- **Client**: Provides the user-facing interface (CLI/GUI), creates a gRPC channel to the server, and invokes RPC methods (Register, Login, SendMessage, etc.) through the generated stub.

```
               +-------------------+
                |   ChatClientApp   |
                |   (GUI/CLI/...)   |
                +---------+---------+
                          |
                   (calls methods)
                          |
                  +-------v--------+
                  |   ChatClient   |
                  |(gRPC Stub/API) |
                  +-------+--------+
                          | TLS
                          |
    ~~~~~~~~~~~~~~~~~~~~~~ Network ~~~~~~~~~~~~~~~~~~~~~~~~~
                          |
                   +------v-------+
                   |   gRPC       |
                   |   Server     |
                   +------^-------+
                          |
                        SQLite
```

---

# 4. Package Structure

```
ChatApp_gRPC/
├── proto/
│   └── chat.proto        <-- The gRPC service definition
├── proto_generated/
│   ├── chat_pb2.py       <-- Auto-generated from chat.proto
│   ├── chat_pb2_grpc.py  <-- Auto-generated from chat.proto
├── modules/
│   ├── __init__.py
│   ├── chatclient.py     <-- Chat client logic (uses stubs)
│   ├── chatclientapp.py  <-- Tkinter GUI
│   └── chatserver.py     <-- gRPC server implementation
├── docs/
│   └── Documentation.md  <-- This documentation file
├── tests/
│   └── test_chat.py     <-- Unit tests
└── certs/
    ├── server.crt       <-- Server certificate
    └── server.key       <-- Server private key
```

- **modules/**: Core application modules (server, client, generated gRPC code, configuration).
- **tests/**: Collection of unit and integration tests.
- **logging/**: Log files, including `server.log`.

---

# 5. Core Components

## ChatClient

**File**: `modules/chatclient.py`

**Description**:  
Provides a Python interface to the gRPC server. Responsible for:

- Establishing a gRPC channel with TLS.
- Creating a `ChatServiceStub` from `chat_pb2_grpc`.
- Invoking remote methods (Register, Login, SendMessage, etc.).
- Managing session state (`session_id`) locally after a successful login.
- Offering a function to initiate a streaming call for real-time messages.

**Key Responsibilities**:

- Encapsulate all client-to-server RPC calls behind easy-to-use methods.
- Maintain the user’s authentication session (`session_id`).
- Provide a background listener (via `Listen`) for live message streaming if needed.

## ChatClientApp

**File**: `modules/chatclientapp.py`

**Description**:  
A Tkinter-based GUI for user interaction that calls into `ChatClient`. Handles:

- Authentication flow (login, register, delete account).
- Sending messages.
- Listing user accounts.
- Reading and displaying new messages.
- Listening in real time for incoming messages (using the gRPC streaming method).

**Key Responsibilities**:

- Provide a user interface with buttons/fields for each major action.
- Translate user actions into gRPC requests by calling `ChatClient.send_request()`.
- Receive and display server responses or streaming messages in the GUI.

## ChatServer

**File**: `modules/chatserver.py`

**Description**:  
Implements the gRPC service (`ChatService`) defined in `chat.proto`. Responsibilities include:

- Managing user accounts in SQLite (with bcrypt for password hashing).
- Storing messages, marking them as delivered, and retrieving them as needed.
- Handling real-time streaming for users who have invoked the `Listen` call.
- Enforcing authentication and validating `session_id` tokens for each request.

**Key Responsibilities**:

- Start and configure the gRPC server with TLS credentials.
- Implement each method from `ChatService` (Register, Login, SendMessage, etc.).
- Interact with the database (create tables, run queries, store messages).
- Keep track of connected/streaming clients to push messages in real time.

---

# 6. Supported gRPC Methods

The `chat.proto` file defines the following RPCs on the `ChatService`:

### Register
- **Request**: `RegisterRequest(username, password)`
- **Response**: `RegisterResponse(status, content)`

### Login
- **Request**: `LoginRequest(username, password)`
- **Response**: `LoginResponse(status, session_id, unread_messages, error)`

### SendMessage
- **Request**: `SendMessageRequest(session_id, from_user, to_user, content)`
- **Response**: `SendMessageResponse(status, content, error)`

### ReadMessages
- **Request**: `ReadMessagesRequest(session_id, from_user, count)`
- **Response**: `ReadMessagesResponse(status, messages, error)`

### ListAccounts
- **Request**: `ListAccountsRequest(session_id, pattern)`
- **Response**: `ListAccountsResponse(status, accounts, error)`

### DeleteMessages
- **Request**: `DeleteMessagesRequest(session_id, from_user, message_ids[])`
- **Response**: `DeleteMessagesResponse(status, content, messages, error)`

### DeleteAccount
- **Request**: `DeleteAccountRequest(session_id, username)`
- **Response**: `DeleteAccountResponse(status, content, error)`

### Listen (streaming)
- **Request**: `ListenRequest(session_id, username)`
- **Response**: `stream ListenResponse` (pushes messages in real time)

---

# 7. Security & TLS

- **gRPC TLS**:
  - The server is configured with TLS credentials (server certificate and private key).
  - The client can verify the server certificate using a root CA file.
- **Password Security**:
  - Passwords are hashed with bcrypt before being stored in the SQLite database.

---

# 8. Data Persistence

- **SQLite**:
  - **users table**: `(username TEXT PRIMARY KEY, password TEXT)`
  - **messages table**: `(id INTEGER PRIMARY KEY, from_user TEXT, to_user TEXT, content TEXT, delivered INTEGER)`
- **Migrations**:
  - The server creates required tables automatically if they do not exist.

---

# 9. Real-Time Message Delivery

**Mechanism**:
- After a user logs in, they can call the `Listen` method.
- The server uses a gRPC stream (`ListenResponse`) to push new messages to the client as soon as they arrive.
- If streaming is interrupted, undelivered messages remain in the database until explicitly retrieved via `ReadMessages`.

---

# 10. Design Principles

- **Modularity & Separation of Concerns**:
  - The business logic (authentication, message persistence) is within the gRPC service implementation.
  - The client focuses on making RPC calls rather than low-level networking.
- **Encapsulation**:
  - The server side hides database interaction and authentication details behind gRPC service methods.
  - The client side hides the complexities of channel creation and stub invocation.
- **Extensibility**:
  - Adding new features involves defining new RPC methods in `chat.proto` and implementing them in `chatserver.py`.
  - Additional streaming or unary RPCs can be easily introduced without breaking existing services.

---

# 11. Quick Start Guide

## Prerequisites

- Python 3.8+ (for gRPC, asyncio, etc.)
- `grpcio` and `grpcio-tools` for Python (`pip install grpcio grpcio-tools`)
- SQLite (typically included in Python installations)
- `tkinter` (standard library; needed for GUI)
- `bcrypt` (for password hashing)

## Installation

1. Clone the repository:
   ```
   git clone git@github.com:WarrenZhu050413/CS262_DistributedSystems.git
   cd CS262_DistributedSystems/ChatApp
   ```

2. Generate gRPC code (if not already generated):
   ```
   python -m grpc_tools.protoc \
       --python_out=./modules \
       --grpc_python_out=./modules \
       -I=./modules \
       ./modules/chat.proto
   ```
   This command will create `chat_pb2.py` and `chat_pb2_grpc.py` in the `modules/` directory.

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Running the Server

1. Obtain or generate TLS credentials:
   ```
   openssl req -new -x509 -days 365 -nodes \
       -out server.crt \
       -keyout server.key
   ```

2. Configure:
   - Update `chatserver.py` to point to the certificate and key paths.

3. Start the gRPC server:
   ```
   python -m modules.chatserver
   ```
   By default, it listens on the configured HOST/PORT (e.g., `0.0.0.0:50051`).

## Running the Client

1. Start the Tkinter GUI:
   ```
   python -m modules.chatclientapp
   ```

2. Perform actions:
   - Register new accounts.
   - Log in to retrieve a session.
   - Send/read/delete messages.
   - Stream real-time updates via `Listen`.

---

# 12. Testing

- **Test Files**: Located in the `tests/` directory (e.g., `test1.py`, `test2.py`, etc.).
- **Running Tests**:
  ```
  cd CS262_DistributedSystems
  python -m ChatApp.tests.test1
  ```
  (Adjust the test file name as needed.)

---

# 13. Logging

- **Configuration**: Logging is typically configured in `ChatServer.setup_logging()` (or similar initialization).
- Logs are written to `logging/server.log`.
- The logging level defaults to `DEBUG` (can be changed to `INFO` or `WARNING`).

---

# 14. Extensibility

- **Adding a New RPC Method**:
  1. Edit `chat.proto` to add the RPC definition.
  2. Regenerate Python stubs via `grpc_tools.protoc`.
  3. Implement the new method in `chatserver.py` (and optionally surface it in `chatclient.py` / `chatclientapp.py`).

- **Adding New Fields**:
  1. Modify the relevant request/response message in `chat.proto`.
  2. Regenerate stubs; update server logic to handle new fields.
  3. Update client code to populate these fields.

---

# 15. Code Reference

## proto/chat.proto

Defines the `ChatService` and all request/response message types:

```proto
syntax = "proto3";

package chat;

service ChatService {
  rpc Register (RegisterRequest) returns (RegisterResponse);
  rpc Login (LoginRequest) returns (LoginResponse);
  rpc SendMessage (SendMessageRequest) returns (SendMessageResponse);
  rpc ReadMessages (ReadMessagesRequest) returns (ReadMessagesResponse);
  rpc ListAccounts (ListAccountsRequest) returns (ListAccountsResponse);
  rpc DeleteMessages (DeleteMessagesRequest) returns (DeleteMessagesResponse);
  rpc DeleteAccount (DeleteAccountRequest) returns (DeleteAccountResponse);
  rpc Listen (ListenRequest) returns (stream ListenResponse);
}

// Message definitions go here ...
```

## modules/chat_pb2.py and modules/chat_pb2_grpc.py

- Auto-generated by the Protobuf compiler (`grpc_tools.protoc`). Do not edit manually.
- `chat_pb2.py`: Contains Python classes for all messages declared in `chat.proto`.
- `chat_pb2_grpc.py`: Contains the generated gRPC client (`ChatServiceStub`) and server classes.

## modules/chatclient.py

- **Class**: `ChatClient`
- **Description**:
  - Creates a gRPC channel with TLS credentials.
  - Initializes a `ChatServiceStub`.
  - Exposes a `send_request(...)` method (and other convenience methods) that map Python calls to gRPC stubs, e.g.:
    ```python
    def send_request(self, action: str, from_user: str, to_user: str, password: str, msg: str) -> Dict[str, Any]:
        if action == "register":
            ...
            response = self.stub.Register(request)
            ...
    ```
  - Stores `session_id` after successful login.

## modules/chatclientapp.py

- **Class**: `ChatClientApp`
- **Description**:
  - A Tkinter GUI that collects user input and translates it into calls on `ChatClient.send_request()`.
  - Displays responses in a text area or via pop-ups.
  - Optionally starts a background thread or uses async calls to stream new messages from `stub.Listen(...)`.

## modules/chatserver.py

- **Key Classes/Functions**:
  - `ChatServer`: Implements the generated `ChatServiceServicer` from `chat_pb2_grpc`.
  - `Register`, `Login`, `SendMessage`, `ReadMessages`, `ListAccounts`, `DeleteMessages`, `DeleteAccount`, `Listen`: Each method corresponds to a gRPC service method.
  - **Database Operations**: Creates or updates SQLite tables, queries for messages/users, etc.
  - `serve()`: Configures TLS credentials, starts the gRPC server on a specified port, and blocks until shutdown.

