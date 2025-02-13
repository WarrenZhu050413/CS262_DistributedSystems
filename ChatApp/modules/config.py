# Server configuration
HOST = "0.0.0.0"
PORT = 54401

# Database configuration
DB_FILE = "users.db"

# Security configuration
CERT_FILE = "ChatApp/security/server.crt"
KEY_FILE = "ChatApp/security/server.key"

# Logging configuration
LOG_FILE = "ChatApp/logging/server.log"

# Supported actions
SUPPORTED_ACTIONS = ["register", "login", "message", "list_accounts", "read_messages", "listen"]
