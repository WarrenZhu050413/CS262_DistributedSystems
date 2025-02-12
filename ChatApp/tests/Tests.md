# ChatApp Test Documentation

## Overview
The ChatApp test suite consists of three main test files that cover different aspects of the application's functionality:

## 1. Core Functionality Tests (test1.py)
Tests basic user operations and authentication:

- **User Registration and Login Flow**
  - Complete flow of registration, login and messaging
  - Validates successful user registration
  - Verifies login with correct credentials
  - Tests message sending after login
  - Validates session ID handling

- **Authentication Edge Cases** 
  - Login attempts with non-existent usernames
  - Duplicate username registration prevention
  - Login attempts with incorrect passwords

## 2. Messaging Tests (test2.py) 
Tests message delivery and handling:

- **Real-time Messaging**
  - Message delivery between online users
  - Immediate delivery verification
  - Listener callback functionality
  - SSL socket cleanup

- **Offline Message Handling**
  - Message storage for offline users
  - Message retrieval upon login
  - Read messages functionality

- **Error Cases**
  - Message sending to non-existent users
  - Server error response validation

## 3. Integration Tests (test3.py)
End-to-end tests covering system interactions:

- **Account Management**
  - Account deletion flow
  - Post-deletion login attempts

- **Message Operations**
  - Message deletion
  - Batch message handling (20 messages)
  - Message persistence verification

- **User Registration**
  - Bulk user registration (100 users)
  - Long username support (50 characters)
  - Special character handling in usernames

### Technical Implementation
- Tests use real network I/O and SQLite database
- Server runs on random ports for isolation
- SSL/TLS encryption enabled
- File-based SQLite database for persistence
- Shared ChatClient instance across tests
- Background thread for server operation
- Proper cleanup of resources after tests

The test suite provides comprehensive coverage across unit tests and integration tests, ensuring reliability of core functionality, messaging, and system integration.