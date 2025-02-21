# ChatApp Documentation

## Table of Contents
- [ChatApp Documentation](#chatapp-documentation)
  - [Table of Contents](#table-of-contents)
  - [1. Introduction](#1-introduction)
  - [2. Features](#2-features)
  - [3. Architecture](#3-architecture)
  - [4. Package Structure](#4-package-structure)
  - [5. Core Components](#5-core-components)
    - [WireMessage (Base Class)](#wiremessage-base-class)
    - [JSONWireMessage](#jsonwiremessage)
    - [BinaryWireMessage](#binarywiremessage)
    - [ChatClient](#chatclient)
    - [ChatClientApp](#chatclientapp)
    - [ChatServer](#chatserver)
  - [6. Supported Actions](#6-supported-actions)
  - [7. Security \& SSL/TLS](#7-security--ssltls)
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
    - [`modules/wiremessage.py`](#moduleswiremessagepy)
    - [`modules/jsonwiremessage.py`](#modulesjsonwiremessagepy)
    - [`modules/binarywiremessage.py`](#modulesbinarywiremessagepy)
    - [`modules/chatclient.py`](#moduleschatclientpy)
    - [`modules/chatclientapp.py`](#moduleschatclientapppy)
    - [`modules/chatserver.py`](#moduleschatserverpy)

---

## 1. Introduction
**ChatApp** is a modular chat application that uses either JSON or Binary wire protocols for client-server communication. It demonstrates a clean separation of concerns, where each layer (e.g., UI, network, business logic) is clearly delimited, making the system more robust, secure, and extensible.

## 2. Features
- **Multiple Wire Protocol Support**: Easily switch between JSON and Binary formats.
- **Modular Design**: Clean separation of concerns and well-defined inheritance hierarchy.
- **User Account Management**: Create, list, authenticate, and delete user accounts.
- **Messaging**: Send messages to individual users and retrieve (including real-time) messages.
- **SSL/TLS Encryption**: Optionally secure communications over TLS, with certificate-based verification.
- **Database Persistence**: Store and retrieve user credentials and undelivered messages using SQLite.

## 3. Architecture
ChatApp follows a client-server model:
- **Server**: Manages user accounts, message storage, real-time notifications, and handles multiple simultaneous client connections.
- **Client**: Establishes connections to the server, encodes/decodes messages according to a chosen protocol, and provides a user-facing interface.

```
                +-------------------+
                |   ChatClientApp   |
                |   (GUI/CLI/...)   |
                +---------+---------+
                          |
                   (calls methods)
                          |
                  +-------v-------+
                  |   ChatClient  |
                  | (Connection,  |
                  |   Protocol)   |
                  +-------+-------+
                          | SSL/TLS
                          |
    ~~~~~~~~~~~~~~~~~~~~~~ Network ~~~~~~~~~~~~~~~~~~~~~~~~~
                          |
                    +-----v-----+
                    | ChatServer |
                    +-----+-----+
                          |
                         DB
```

## 4. Package Structure
```
ChatApp/
├── modules/
│   ├── __init__.py
│   ├── config.py
│   ├── wiremessage.py
│   ├── jsonwiremessage.py
│   ├── binarywiremessage.py
│   ├── chatclient.py
│   ├── chatclientapp.py
│   └── chatserver.py
├── tests/
│   ├── test1.py
│   ├── test2.py
│   ├── test3.py
│   ├── test4.py
│   └── test5.py
└── logging/
    └── server.log
```
- **`modules/`**: Contains core application modules (client, server, protocol handlers, configuration).
- **`tests/`**: Collection of unit and integration tests.
- **`logging/`**: Log files, including `server.log`, are stored here.

## 5. Core Components

### WireMessage (Base Class)
- **File**: `modules/wiremessage.py`  
- **Description**:  
  An abstract base class (`ABC`) defining the general interface for wire protocols. It declares the methods that any subclass must implement (e.g., `make_wire_message`, `parse_wire_message`, and `read_wire_message`). This ensures a consistent interface across different wire protocols.
- **Key Responsibilities**:
  - Enforce method signatures for encoding/decoding.
  - Provide a robust foundation for building new wire protocols.

### JSONWireMessage
- **File**: `modules/jsonwiremessage.py`  
- **Description**:  
  Implements a JSON-based protocol by serializing dictionaries into JSON and framing them with a 4-byte length prefix. Then uses JSON to deserialize the bytestream.
- **Key Responsibilities**:
  - Convert Python dictionaries to JSON message to be sent over the wire.
  - Read/write data over a socket with a length-prefix approach.
- **Ideal Use Cases**:
  - Human-readable transmissions (easier debugging).
  - Rapid development where clarity outweighs performance overhead.
- **Problems**:
  - High overhead because JSON is a text-based protocol that preserves the entire message in the bytestream.

### BinaryWireMessage
- **File**: `modules/binarywiremessage.py`  
- **Description**:  
  Implements a more compact wire protocol by using Python’s `repr`/`ast.literal_eval` approach for dictionary encoding. Like the JSON approach, it also uses a 4-byte length prefix.
- **Key Responsibilities**:
  - Provide more efficient encoding than raw JSON (though still textual under the hood).
  - Preserve the same structure (length prefix, dictionary-based messaging).
- **Ideal Use Cases**:
  - Faster transmission and parsing than JSON.
  - Potential future enhancements for true binary formats or compression.
- **Problems**:
  - Hard to maintain because it is a binary protocol and not using external packages.

### ChatClient
- **File**: `modules/chatclient.py`  
- **Description**:  
  Handles all client-side networking tasks, including:
  1. Establishing SSL/TLS connections.
  2. Sending and receiving messages via a chosen wire protocol (here, `WireMessageBinary`).
  3. Managing session state (e.g., `session_id`).
  4. Starting/stopping a persistent listener thread for real-time updates.
- **Key Responsibilities**:
  - Encapsulate socket logic (connection, data sending/receiving).
  - Keep track of current authenticated session information.
  - Provide thread-based background listening for incoming messages.

### ChatClientApp
- **File**: `modules/chatclientapp.py`  
- **Description**:  
  A **Tkinter**-based GUI for user interaction, specifies what messages the client can send to the server and how the client will display the response from the server. Handles:
  1. Authentication flow (login, register, delete account).
  2. Sending messages to recipients.
  3. Searching for user accounts.
  4. Displaying incoming messages, including real-time message push.

There is a button for each action that the client can perform. When the button is clicked, the client will send the action to the server and display the response in the GUI.
- **Key Responsibilities**:
  - Present a user interface and capture input (usernames, messages, patterns).
  - Convert user actions into method calls on `ChatClient`.
  - Render server responses in a user-friendly way (GUI components).
  - Handle real-time message push in the background.
### ChatServer
- **File**: `modules/chatserver.py`  
- **Description**:  
  A multi-client server that:
  1. Listens on a given port for SSL/TLS connections.
  2. Accepts incoming requests and decodes them via the `WireMessageBinary` class.
  3. Manages user accounts in an SQLite database (with `bcrypt` for password hashing).
  4. Stores and routes messages, with optional real-time delivery.
- **Key Responsibilities**:
  - Create and maintain an event loop for non-blocking I/O (`selectors`).
  - Validate sessions for each incoming request.
  - Interact with the database for authentication, message storage/retrieval, and account queries.
  - Broadcast or push messages to clients that are actively listening.
- **Database Schema**:
  - **`users`** table: `(username TEXT PRIMARY KEY, password TEXT)`
  - **`messages`** table: `(id INTEGER PRIMARY KEY, from_user TEXT, to_user TEXT, content TEXT, delivered INTEGER)`

## 6. Supported Actions
The client and server both recognize the following actions in `WireMessage` objects:

1. **CREATE_ACCOUNT / `register`**  
   - **Description**: Creates a new user account.  
   - **Parameters**: `username, password`  
   - **Returns**: `{"status": "ok"}` on success or `{"status": "error"}` on failure.

2. **LOGIN / `login`**  
   - **Description**: Authenticates users.  
   - **Parameters**: `username, password`  
   - **Returns**: `session_id` on success, or `error`.

3. **LIST_ACCOUNTS / `list_accounts`**  
   - **Description**: Lists all registered accounts, optionally filtered by a pattern.  
   - **Parameters**: `pattern (wildcard)`  
   - **Returns**: A list of matching `username`s.

4. **SEND_MESSAGE / `message`**  
   - **Description**: Sends a message to a user.  
   - **Parameters**: `from_user, to_user, content`  
   - **Returns**: Delivery status.

5. **GET_MESSAGES / `read_messages`**  
   - **Description**: Retrieves undelivered messages for the current user.  
   - **Parameters**: `count` (how many messages to fetch)  
   - **Returns**: A list of messages.

6. **DELETE_ACCOUNT / `delete_account`**  
   - **Description**: Removes the user account, including all associated messages.  
   - **Parameters**: `username`  
   - **Returns**: Success or error status.

7. **DELETE_MESSAGES / `delete_messages`**  
   - **Description**: Deletes messages with specified IDs for the requesting user.  
   - **Parameters**: Comma-separated string of message IDs.  
   - **Returns**: A success message, plus any remaining messages.

8. **LISTEN / `listen`** (default activated in the background when the user logs in) 
   - **Description**: Upgrades the connection to a persistent listen socket so the server can push real-time messages.  
   - **Parameters**: `username, session_id`  
   - **Returns**: `{"status": "ok"}` if the session is valid.

## 7. Security & SSL/TLS
- **SSL Context**:  
  The server is wrapped in an `SSLContext` using `server_side=True` to offer TLS encryption.  
- **Client Certificates**:  
  The client uses a CA file to verify server certificates, but currently sets `verify_mode=ssl.CERT_NONE` (meaning it does not fully enforce certificate validation). This can be changed for stricter security.  
- **Password Security**:  
  Passwords are stored in the database only after hashing with `bcrypt` (including a salt).

## 8. Data Persistence
- **SQLite** is used for storing:
  1. **User Accounts**: `username` (primary key) + hashed `password`.
  2. **Messages**: `from_user, to_user, content, delivered`.
- **Migrations**:  
  ChatApp automatically creates required tables if they do not exist. Additional migrations can be added as needed.

## 9. Real-Time Message Delivery
- **Mechanism**:  
  - Once a client logs in successfully, it optionally initiates a `listen` action.  
  - The server registers the listening user’s connection in `self.listeners`.  
  - Incoming messages for that user are pushed in real-time via the open socket.  
  - If real-time delivery fails, messages remain undelivered in the database until `read_messages` is called.

## 10. Design Principles

1. **Modularity & Separation of Concerns**  
   - Protocol logic (e.g., JSON, Binary) is separate from the business logic.  
   - The client handles connection management; the server manages data storage and user sessions.

2. **Inheritance Hierarchy**  
   - `WireMessage` is the abstract base.  
   - `JSONWireMessage` and `BinaryWireMessage` extend the functionality with specific encoding/decoding strategies.

3. **Encapsulation**  
   - Each component (client, server, wire protocol) hides its internal details from others.  
   - The `ChatClientApp` is only concerned with the methods exposed by `ChatClient`.

4. **Extensibility**  
   - New protocols can be integrated by creating a class that extends `WireMessage`.
   - Each protocol contains a protocol version number.
   - Additional features can be added without altering core functionalities (plugin-friendly).

## 11. Quick Start Guide

### Prerequisites
- Python 3.8+ (For `asyncio` or `selectors`, SSL, etc.)
- `bcrypt` and `ssl` libraries (often included by default in Python distributions).
- A valid certificate/key pair for TLS (self-signed or from a CA).
- SQLite (typically included in standard Python installations).
- `tkinter` (standard library)

### Installation
1. **Clone the repository**:
   ```bash
   git clone git@github.com:WarrenZhu050413/CS262_DistributedSystems.git
   cd CS262_DistributedSystems/ChatApp
   ```

2. **Install dependencies** (example using Conda or pip):
   ```bash
   conda env create -f ChatApp/modules/environment.yml
   ```

### Running the Server
1. **Generate SSL certificates** (if you don’t already have them):
   ```bash
   openssl req -new -x509 -days 365 -nodes \
       -out server.crt \
       -keyout server.key
   ```
2. **Configure**:  
   Check the `ChatServer` constructor arguments for paths to the certificate and key files.
3. **Start the server**:
   ```bash
   python -m modules.chatserver
   ```
   By default, it listens on the configured `HOST` and `PORT` (e.g., `0.0.0.0:5000`).

### Running the Client
1. **Launch the GUI**:
   ```bash
   python -m modules.chatclientapp
   ```
2. **Use the interface** to:
   - Register a new account.
   - Log in.
   - Send messages.
   - View message status and real-time updates.

## 12. Testing
- **Test Files**: Located in the `tests/` directory (`test1.py`, `test2.py`, etc.).  
- **Running Tests**:
  ```bash
  cd CS262_DistributedSystems
  python -m ChatApp.tests.test[version]
  ```

## 13. Logging
- **Configuration**: `logging` is configured in `ChatServer.setup_logging()`.  
  - Logs are written to `logging/server.log`.  
  - Logging level is set to `DEBUG` by default (can be changed to `INFO` or `WARNING` in production).
  - Each message that the server recieves and each action that the server performs is logged.

## 14. Extensibility
- **Adding a New Protocol**:  
  1. Create a subclass of `WireMessage` (e.g., `AdvancedBinaryWireMessage`).  
  2. Implement `make_wire_message`, `parse_wire_message`, and `read_wire_message`.  
  3. Update the client and server code if you want to switch to or allow the new protocol.
- **Adding New Actions**:  
  1. Define the action logic in `ChatServer.handle_request()`.  
  2. Provide the necessary DB operations (if needed).  
  3. Expose a corresponding method in `ChatClient`, and link it in `ChatClientApp` (if the client UI needs it).

## 15. Code Reference

### `modules/wiremessage.py`
Abstract class defining the interface for all wire protocol implementations.  
- **Key Methods**:
  - `make_wire_message(...)`
  - `parse_wire_message(...)`
  - `read_wire_message(...)`

### `modules/jsonwiremessage.py`
Implements the JSON-based wire protocol:
- **`encode_message(message: dict) -> bytes`**: Serializes a Python dictionary into JSON, prefixes with length.  
- **`make_wire_message(...) -> bytes`**: Constructs a message dictionary, then encodes it.  
- **`read_wire_message(sock) -> bytes`**: Reads the length prefix and then the JSON payload.

### `modules/binarywiremessage.py`
Implements a simpler binary protocol by using `repr()` for serialization:
- **`encode_message(message: dict) -> bytes`**: Uses a 4-byte length + the `repr` of the dictionary.  
- **`parse_wire_message(wire_message: bytes) -> dict`**: Converts a UTF-8 string back into a Python dictionary with `ast.literal_eval`.

### `modules/chatclient.py`
- **Class**: `ChatClient`  
- **Responsibilities**:
  - Establish SSL sockets to the server.
  - Send requests and receive responses using the `WireMessageBinary` class.
  - Manage session IDs.
  - Start/stop a background listener for pushed messages.

### `modules/chatclientapp.py`
- **Class**: `ChatClientApp`  
- **Description**:
  - A Tkinter-based GUI that processes user input and displays server responses.
  - Handles login, registration, message sending, account deletion, and more.
  - Provides a callback `handle_incoming_message(...)` for real-time messages.

### `modules/chatserver.py`
- **Class**: `ChatServer`  
- **Key Methods**:
  - `start()`: Sets up SSL, starts listening, and processes connections with `selectors`.
  - `handle_request(req, key) -> dict`: Core dispatcher for all supported actions.
  - `handle_{action}()`: Helper methods implementing each user action.
  - `setup_database()`: Initializes or migrates the SQLite database.
  - `setup_logging()`: Configures the logging system.

---