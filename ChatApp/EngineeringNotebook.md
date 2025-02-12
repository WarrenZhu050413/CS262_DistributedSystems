# Engineering Notebook

## 06-02-2025 (Meeting)
**Brainstorming the project together.**

Decided to:
1. Start to build the chat app without the GUI before adding the GUI on.  
2. Use the `selectors` module for async I/O rather than using multi-threading, since this is what was shown in the lectures.  
3. Use SQLite as the database for persistent storage.

---

## 09-02-2025 (Defining the modules of the project)
Build a basic front-end and back-end first. The aim is that they can exchange messages with each other via TCP.

- **Back-end**: Base it on the `countAndTrans.py` example on Canvas.  
- **Front-end**: Use Flask and `tkinter` for the GUI (as recommended on Ed).  
- **Dependencies**: Use `environment.yaml` to define the dependencies for the project. We chose `python=3.11` because it is faster.

---

## 10-02-2025 (Beginning to Build)
- **Minimum Message Transfer**  
  - First support JSON only.  
  - The client GUI is minimalistic: one text entry box and a Send button. It sends JSON.  
  - We use the native Python `json` library to parse and build JSON messages.

- **Commands Implemented**  
  1. **Register**  
     ```json
     {
       "action": "register",
       "from": "bob",
       "password": "mypassword"
     }
     ```
     - Test: Do it twice to see whether we get "Username already exists" error.  

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

- **Server Response**  
  - **Successful registration**  
    ```json
    {
      "status": "ok",
      "message": "Registration successful"
    }
    ```
  - **Registration error**  
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
  - **Login response (with session)**  
    ```json
    {
      "status": "ok",
      "session_id": "abcdef123456..."
    }
    ```
  - **Login error message**  
    ```json
    {
      "status": "error",
      "error": "Invalid username or password"
    }
    ```

- **Client Registration**  
  - Client registration is on a separate `register` GUI webpage.  
  - Checks password length < 256 chars, then checks for duplicate username in SQLite.  
  - If successful, inserts `(username, password)` into the SQLite `users` table.  
  - On success, user is directed to the main messaging page, with a “logged in” status.

- **Security**:  
  - We plan to use basic security by hashing the password with `bcrypt` or similar.  
  - The project is not focusing on advanced security, but we will use TLS for transport.

---

## 10-02-2025 (Security)
- Added extra security to the password login/registration process.  
- Decided to use a TLS handshake for the connection. We generated a self-signed certificate for the server:
  ```bash
  openssl req -newkey rsa:2048 -nodes -x509 -days 365 \
    -keyout server.key \
    -out server.crt
  ```
- We use non-blocking handshake to avoid blocking the main thread and improve performance.

---

## 10-02-2025 (Debugging: Testing basic login/registration process with active session management)
- Registered `alice` and `bob`:
  ```json
  {"action": "register", "from": "alice", "password": "mypassword"}
  {"action": "register", "from": "bob", "password": "mypassword"}
  ```
- Checked `users.db` with `sqlite3 users.db .dump`:
  ```sql
  CREATE TABLE users (
              username TEXT PRIMARY KEY,
              password TEXT
          );
  INSERT INTO users VALUES('alice','$2b$12$/MpJ7KaB7QdJ0sdz...');
  INSERT INTO users VALUES('bob','$2b$12$9aHMm0a2nP3...');
  ```
- Then logged in `bob`:
  ```json
  {"action": "login", "from": "bob", "password": "mypassword"}
  ```
  - Got response with `"session_id": "f1c191a014483..."`.

- **Message Problem**:  
  ```json
  {"action": "message", "from": "bob", "to": "alice", "message": "Hello, Alice!"}
  ```
  - The server responded with `{"status": "error", "error": "Invalid session"}`.  
  - **Root Cause**: We forgot to include `session_id` in the outgoing message.  

- **Fix**: The client now stores the session_id from the login response and automatically appends it to any subsequent message requests.

---

## 10-02-2025 (Changing the GUI to auto-generate wire protocol messages)
- Previously, the user had to type JSON by hand, which was error-prone.  
- Now the GUI has multiple input fields (username, password, recipient, message) and automatically assembles them into the correct JSON wire protocol.  
- This approach is more user-friendly.  
- **Implementation**: Wrote a class-based GUI for better organization.  

---

## 10-02-2025 (Refactor the server code to be class-based)
- Moved server functions into a `ChatServer` class.  
- Separated command handling logic (`handle_register`, `handle_login`, `handle_message`, etc.) for clarity.

---

## 10-02-2025 (Add automatic testing)
- Started adding unit tests for registration, login, message sending, and session management.  
- Ensuring that repeated registrations or invalid logins produce correct error responses.

---

## 10-02-2025 (Building receive functionality into the app)
- Currently, when a message is sent, the server prints:
  ```
  [MESSAGE] bob -> alice: hi!
  ```
  But the receiving user does not get a real-time notification in their GUI.  
- Plan for real-time delivery if recipient is online; if offline, message is saved to be fetched later.

---

## 10-02-2025 (Improve Security)
- Noticed that the security certificates were pushed to GitHub by accident.  
- **Action**: Regenerated certificates, placed them in `./security`, and added them to `.gitignore`.

---

## 10-02-2025 (Implement Separation of Concerns in the client code)
- Refactored client code to separate the GUI from wire protocol logic:  
  - `ChatClient` handles network I/O.  
  - `ChatClientApp` handles the GUI and user interaction.

---

## 10-02-2025 (Implement type annotations)
- Added type hints throughout the code to improve readability and maintainability.

---

## 10-02-2025 (Develop more robust message delivery system)
1. Allow wildcard patterns to search for existing users.  
2. Validate that the recipient username exists; if not, return an error.  
3. Simplify the GUI layout with separate buttons for **Login**, **Register**, **Send Message**.  
4. Added **multi-threading** to support real-time messaging when both sender and recipient are online. Offline messages are stored and delivered later.  
5. Display sent messages alongside received messages in the client’s GUI.

---

## 11-02-2025 (Restricting each connection to a single login)
- Changed the code so that once a user logs in on a connection, it cannot be used for a second login.  
- This avoids confusion and potential security issues.

---

## 11-02-2025 (Preparing to migrate away from JSON)
- Goal: keep a human-readable design approach but move to a custom binary format for the wire protocol (more compact, faster).  
- Implemented a `WireMessage` class with these functions:  
  - `make_wire_message(action, from_user, to_user, password, msg, session_id) -> bytes`  
  - `parse_wire_message(wire_message: bytes) -> dict`  
  - `read_wire_message(socket) -> bytes`  
- Currently `WireProtocolJSON` is used, but we plan to implement `WireProtocolBinary` in the same architecture.

---

## 11-02-2025 (Changing import structure to run like a package)
- Reorganized the repository so each module can be imported in a more standard way:
  ```
  python -m ChatApp.server
  python -m ChatApp.client
  ```
- Ensures consistent imports and easier distribution.

---

## 11-02-2025 (Implementing More Unit Tests)
- Testing the message delivery system, including offline/online states, reading stored messages, etc.  
- **Found an error** in a test:
  ```
  FAIL: test_read_messages
    ...
    AssertionError: 'Hello' != ''
  ```
  - **Root Cause**: The message was not stored in the database or not retrieved properly.  
  - Traced it to our JSON serialization logic and fixed it in `self.handle_json_request()`.

---

## 11-02-2025 (Adding Delete Message Functionality)
- Implemented a new “delete” action that removes one or more messages from the server-side storage.  
  - If the user selects message IDs `[2, 3, 4]`, the server will remove them from the DB.  
  - The server returns a success or error JSON (or wire-protocol) response.

---

## 11-02-2025 (Delete User Functionality)
- Implemented a new “delete user” action.  
  - Deletes the user’s entry from `users.db`.  
  - Removes any stored messages for that user.  
  - Terminates the user’s active session if it exists.

---

## 11-02-2025 (Showing number of unread messages)
- Upon successful login, the server checks the database for unread messages for the user.  
- The server returns the count, and the client GUI displays it.

---

## 11-02-2025 (Debugging multi-user environment)
- Verified that specifying the correct network interface (e.g., `HOST = <your_IP_address>`) is essential for testing with multiple people.

---

## 11-02-2025 (Implementing the custom binary message protocol)
- For efficiency, we created our custom binary message protocol, including:  
  1. Custom serializer, taking the string form of the dictionaries and transforming it into an efficient format with special characters
  2. Custom deserializer, efficiently parsing through the string, using the special characters to retrieve the fields and values
- The server reads these fields in sequence to reconstruct the message.  
- This approach avoids complexities of parsing JSON on the wire.
- Since our base JSON implementation passes all information in their byte format, the size of the information passed is the same. However, our custom protocol is more scalable and efficient for larger systems due to its fast encoding and parsing speeds. We compare the efficiency of our protocols below.
![image]('ChatApp/efficiency.png')
- As shown in the plot, our custom protocol is more efficient, achieving an average time around 40% faster than our JSON implementation.

---

## 12-02-2025 (Performance and Scaling Discussion)
1. **Performance Testing**  
   - Will run load tests to see how the server performs under multiple concurrent logins and message sends.  
   - Plan to use a tool like `locust` or a custom Python script with multiple threads/async tasks.  
2. **Scaling**  
   - If we need to support many users, consider optimizing the SQLite usage or switching to a more robust DB like PostgreSQL.  
   - The chosen concurrency model with `selectors` should scale moderately well, but we may explore `asyncio` if needed.  
3. **Next Steps**  
   - Finalize the custom binary protocol implementation for all actions (login, register, message, delete, etc.).  
   - Provide a configuration setting so the client and server can switch between JSON or binary protocols easily.  
   - Expand the test suite to cover all new features (delete user, message deletion, etc.).  

---

## 12-02-2025 (Planned Features and Future Work)
1. **Group Chat**  
   - Extend the `to` field to accept a list of recipients or a group name.  
   - Server would then handle sending to multiple recipients at once.  
2. **Attachments or File Transfers**  
   - Potentially store small files in the database or have a separate file server; we need to define size limits.  
3. **Message Read Receipts**  
   - Add a status to each message row in the database: `delivered`, `read`, etc.  
   - Update once the client confirms reading.  
4. **Refine Security**  
   - Use more robust hashing (`bcrypt` with stronger parameters or `argon2`).  
   - Explore OAUTH / JWT for session management if scaling up.  
5. **Docker Containerization**  
   - Make the deployment simpler by packaging the server (and possibly the client) into a Docker image.  
