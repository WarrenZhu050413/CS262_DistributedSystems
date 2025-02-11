# Engineering Notebook

## 06-02-2025 (Meeting)
Brainstorming the project together.

Decided to:

1. Start to build the chat app without the GUI before adding the GUI on
2. Use selectors module for async-io rather than use mutli-threading since this is what was shown to us in the lectures
3. Use SQLite as the database for persistent storage

## 09-02-2025 (Defining the modules of the project)

Build a basic front-end and back end first. The aim is that they can exchange messages with each other via TCP. 

Build the backend from the code `countAndTrans.py` on canvas. Build the front-end using Flask. Use `tkinter` for the UI (recommended on Ed).

Use an environment.yaml file to define the dependencies for the project. Use python=3.11 because it is faster.

## 10-02-2025 （Beginning to Build)

Starting the project, building up minimum message transfer functionality. First support JSON only. The client GUI is minimalistic, just a text entry box and a send button, and needs to write in JSON. **Later can help users format their messages into JSON**. We use the native JSON library of python to parse the JSON messages into a dictionary.

We will implement three commands: registration, login, and message. Each command will be a JSON object with the following fields, prefixed with a 4 byte length field:

1. **Register**  
   ```json
   {
     "action": "register",
     "from": "bob",
     "password": "mypassword"
   }
   ```
Test: Do it twice to see whether get "Username already exists" error.

2. **Login**  
   ```json
   {
     "action": "login",
     "from": "bob",
     "password": "mypassword"
   }
   ```

3. **Message**  
   ```json
   {
     "action": "message",
     "from": "bob",
     "to": "alice",
     "message": "Hello, Alice!"
   }
   ```

The server will respond with a **JSON** object:

- Successful registration:
  ```json
  {
    "status": "ok",
    "message": "Registration successful"
  }
  ```
- Registration error message:
   - Username already exists
   ```json
   {
      "status": "error",
      "error": "Username already exists"
   }
   ```
  - Password is too long
   ```json
   {
      "status": "error",
      "error": "Password is too long"
   }
   ```
- Login response (with session):
  ```json
  {
    "status": "ok",
    "session_id": "abcdef123456..."
  }
  ```
- Login error message:
  ```json
  {
    "status": "error",
    "error": "Invalid username or password"
  }
  ```



First, support client registration.

- Client registration should happen in a separate register GUI webpage. 
The registration includes a username and a password. The password should be first be checked to be shorter than $2^8 = 256$ characters, then the username should be checked against duplication in the SQLite database (using a SQLite query, perhaps using the python built-in functionality for SQLite and the python-specific SQLite language) on the server once the server receives it. If there is no username duplication and the password is short enough, then the username and password pair is logged in a SQLite database with two columns, username and password. At last, redirect the user into a page that supports message passing, with a status indicating that the user is logged in. 

The logging in functionality should support sessions for continuous authentication, and the password passing should have security by using hashes, but we don't need too much more security at this point.

## 10-02-2025 (Security)

Adding extra security to the password login/registration process. Decide to use TLS handshake for connection. Generated a self-signed certificate for the server.

Use non-blocking handshake to avoid blocking the main thread and improve performance.

```
openssl req -newkey rsa:2048 -nodes -x509 -days 365 \
  -keyout server.key \
  -out server.crt
```

We should write our code to be as modular as possible. The JSON message to be passed.

## 10-02-2025 Debugging: Testing a basic login/registration process, active session management
I first registered alice, and then bob.

```json
{"action": "register", "from": "alice", "password": "mypassword"}
{"action": "register", "from": "bob", "password": "mypassword"}
```

Then I checked the database file `users.db` to see whether the registration is successful.
```json
❯ sqlite3 users.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT
        );
INSERT INTO users VALUES('alice','$2b$12$/MpJ7KaB7QdJ0sdz7bAdGetr/EELX9g14CaIhxZ10CmpZACBF371a');
INSERT INTO users VALUES('bob','$2b$12$9aHMm0a2nP33jLLt7uoHCeSaACZCG46JIICZOO70j8pizeJ8keCrm');
COMMIT;
```

Then I logged in bob and sent a message to alice.

```json
{"action": "login", "from": "bob", "password": "mypassword"}
```
Server responded with JSON {"status": "ok", "session_id": "f1c191a014483..."}

But the message is not delivered.
```json
{"action": "message", "from": "bob", "to": "alice", "message": "Hello, Alice!"}
```
Server responded with JSON {"status": "error", "error": "Invalid session"}

My hypothesis is that somehow the session_id is not being logged.

Will debug this by adding logging to the code.

1. **Register**  
   ```json
   {
     "action": "register",
     "from": "bob",
     "password": "mypassword"
   }
   ```
Test: Do it twice to see whether get "Username already exists" error.

1. **Login**  
   ```json
   {
     "action": "login",
     "from": "bob",
     "password": "mypassword"
   }
   ```

2. **Message**  
   ```json
   {
     "action": "message",
     "from": "bob",
     "to": "alice",
     "message": "Hello, Alice!"
   }
   ```

Found out the reason is that we forgot to add the session_id to the message. However, this is not very user friendly, so will configure the client to remember the session_id after logging in and append the session_id to the message.

## 10-02-2025 Changing the GUI to automatically prepare the client-side information into the correct wire protocol format
The gui before required the client to type the message into the correct format (e.g. type JSON). This is error-prone. A better design is to parse the user input into the correct wire protocol format automatically, with multiple input text boxes for different fields in the wire protocol.

When done this, found that the GUI code becomes harder to maintain. Therefore writing it as a class-based GUI.

This ended up being cleaner. Also passed the session_id to the server automatically, and now can send messages to the server.

## 10-02-2025 Refactor the server code to be class-based

Finished refactoring. Put previous functins into the ChatServer class.

## 10-02-2025 Add automatic testing


## 10-02-2025 Building receive functionality into the app

Currently, when we send a message, we only have it printed out in the terminal `[MESSAGE] bob -> alice: hi!`, but not actually sent to the other user. We now need to build the logic to do so.

In order to do so, we will experiment with the following protocol:

```
When user_from -> user_to: message:
   check_user_from_valie()
   If user_to in active_sessions.values():
      push_message_to_user_to()
   If user_to not in active_sessions.values():
      save_message_to_user_to()

Further, we need to augment the handle_login() function:

handle_login():

```

## 10-02-2025 Improve Security
Realized that the security certificate was pushed to Github. Regenerated the certificate and put the `./security` folder into `.gitignore`.

## 10-02-2025 Implement Separation of Concerns in the client code

Refactor the client code to separate out the GUI code from the wire protocol code. Implemented the class ChatClient for the wire protocol code. Then implemented the class ChatClientApp (child class of ChatClient) for the GUI code.

## 10-02-2025 Implement type annotations

As the code grows, it is becoming more and more difficult to reason about the code. Therefore, implement type annotations to help with the code maintenance.

## 10-02-2025 Develop more robust message delivery system

With most of the funamental architecture in place, we made our message delivery more robust with the following changes.

1. Confirmed that the recipient username exists. If not, then we throw an appropriate error to notify the user.

### Wire Protocol
1. Different types of messages that we need to support

**White Space Handling?**

Client to server:
- {action: send, to: user_name, message: message_content}

server to client:
= {action: message, from: user_name, message: message_content}

JSON Wire Protocol: 
{"action": "send", "to"}

Also, since sending via TCP, needs to delimit each JSON message. Maybe through 

Custom Binary Protocol: 
1. Needs to solve field delimination
   1. Should we prefix the length or have a special character delimiting the field?
   2. Prefixing the length may be better for cleaner code and faster processing
   3. opcode | username_length | username | message_length | message

### System Architecture

#### Server
1. Use Flask? (Easy to use, light-weight, we have experience)
2. Handle concurrent connections (in the handout code)
3. Create users
   1. Log user data in SQLite
      1. username uniqueness
      2. Authorization
4. Message handling
   1. Server accepts chat message from user via `socket`
   2. Server saves it to SQLite database
   3. Server checks whether the recipient is online
   4. If the recipient is online


1: Creating an account. The user supplies a unique (login) name. If there is already an account with that name, the user is prompted for the password. If the name is not being used, the user is prompted to supply a password. The password should not be passed as plaintext. 

2: Log in to an account. Using a login name and password, log into an account. An incorrect login or bad user name should display an error. A successful login should display the number of unread messages.

3: List accounts, or a subset of accounts that fit a text wildcard pattern. If there are more accounts than can comfortably be displayed, allow iterating through the accounts.

1. Send a message to a recipient. If the recipient is logged in, deliver immediately; if not the message should be stored until the recipient logs in and requests to see the message.

5: Read messages. If there are undelivered messages, display those messages. The user should be able to specify the number of messages they want delivered at any single time.

6. Delete a message or set of messages. Once deleted messages are gone.

7. Delete an account. You will need to specify the semantics of deleting an account that contains unread messages.
