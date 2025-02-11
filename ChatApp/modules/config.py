# Server configuration
HOST = "127.0.0.1"
PORT = 54400

# Database configuration
DB_FILE = "users.db"

# Security configuration
CERT_FILE = "ChatApp/security/server.crt"
KEY_FILE = "ChatApp/security/server.key"

# Logging configuration
LOG_FILE = "ChatApp/logging/server.log"

# Supported actions
SUPPORTED_ACTIONS = ["register", "login", "message", "list_accounts", "read_messages", "listen"]
