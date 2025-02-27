# Engineering Notebook: Distributed System Model with Logical Clocks

## Introduction

This notebook documents the design decisions and observations made during the implementation of a distributed system model with logical clocks. The system simulates multiple virtual machines running at different speeds, communicating with each other, and using logical clocks to track event ordering.

## Design Decisions

### Overall Architecture

1. **Multi-threaded Design**: Each virtual machine (VM) is implemented with multiple threads:
   - A listener thread that accepts incoming connections
   - A network queue processor thread that moves messages from the network queue to the message queue
   - A clock thread that runs at the VM's specified clock rate

2. **Two-Queue System**: As specified in the requirements, each VM has:
   - A network queue that is always active and receives incoming messages
   - A message queue that is processed at the VM's clock rate

3. **Socket Communication**: VMs communicate with each other using TCP sockets, with each VM listening on a unique port.

### Virtual Machine Implementation

1. **Clock Rate**: Each VM is assigned a random clock rate between 1-6 ticks per second, implemented as a sleep interval between clock cycles.

2. **Logical Clock**: Each VM maintains a logical clock that is updated according to Lamport's logical clock rules:
   - Increment by 1 for internal events
   - When receiving a message, set to max(local_clock, received_clock) + 1

3. **Event Processing**:
   - If there's a message in the queue, process it and update the logical clock
   - If not, generate a random number (1-10) to determine the event type
   - For events 1-3, send messages to other VMs
   - For events 4-10, simulate an internal event

4. **Logging**: Each VM logs events to its own log file, including:
   - The event type (receive, send, internal)
   - The system time
   - The logical clock value
   - For receive events, the message queue length

### Log Analysis

I've implemented an analysis script (`analyze_logs.py`) that processes the log files and generates insights:

1. **Parsing**: Extracts timestamp, logical clock values, event types, and queue lengths from log entries
2. **Visualization**: Creates plots of logical clock values and queue lengths over time
3. **Statistics**: Calculates queue length statistics and logical clock rates

## Implementation Challenges and Solutions

1. **Socket Connection Handling**: 
   - Challenge: Ensuring all VMs connect to each other correctly during initialization
   - Solution: Implemented a connection system where each VM connects to all others based on known ports

2. **Thread Synchronization**:
   - Challenge: Preventing race conditions between threads
   - Solution: Used Python's thread-safe Queue implementation for the message and network queues

3. **Logical Clock Implementation**:
   - Challenge: Correctly implementing the Lamport clock rules
   - Solution: Used the max(local, received) + 1 rule for message receipt and increment by 1 for other events

## Unit Test Plan

Based on the README requirements, I've identified the following behaviors that should be tested:

### Initialization Tests

1. **Clock Rate Initialization**: Test that each VM initializes with a clock rate between 1-6 ticks per second.
2. **Queue Initialization**: Verify that each VM properly initializes both network and message queues.
3. **Socket Creation**: Test that the VM correctly creates a socket on the specified port.
4. **Logical Clock Initialization**: Verify the logical clock starts at 0.

### Connection Tests

5. **Peer Connection**: Test that VMs can connect to other VMs using socket connections.
6. **Connection Verification**: Verify that a VM confirms connections to all specified peers.

### Message Handling Tests

7. **Network Queue Processing**: Test that messages in the network queue are moved to the message queue.
8. **Message Reception**: Verify that a VM can receive a message from another VM.
9. **Message Sending**: Test that a VM can send messages to other VMs.

### Clock Cycle Tests

10. **Processing Messages**: Verify that if there's a message in the queue, the VM processes it.
11. **Message Queue Update**: Test that the logical clock updates correctly when processing a message.
12. **Random Event Generation**: Verify that when there's no message, a random event (1-10) is generated.
13. **Send Event (Type 1)**: Test that when event type 1 occurs, a message is sent to one VM.
14. **Send Event (Type 2)**: Test that when event type 2 occurs, a message is sent to another VM.
15. **Send Event (Type 3)**: Test that when event type 3 occurs, messages are sent to all VMs.
16. **Internal Event**: Verify that when event type > 3 occurs, an internal event is logged.

### Logical Clock Tests

17. **Logical Clock Increment**: Test that the logical clock increments by 1 for internal events.
18. **Logical Clock Update on Message Receipt**: Verify the logical clock updates correctly when receiving a message (max(local, received) + 1).

### Logging Tests

19. **Message Receipt Logging**: Test that message receipts are properly logged with queue length.
20. **Send Message Logging**: Verify that sending messages is properly logged.
21. **Internal Event Logging**: Test that internal events are properly logged.

### Shutdown Tests

22. **VM Shutdown**: Verify that a VM can be properly shut down, closing all connections.

## Testing Plan

1. Run the system with 3 VMs for at least 1 minute, 5 separate times
2. Collect and analyze logs to observe:
   - Logical clock drift between VMs
   - Message queue lengths
   - Impact of different clock rates on system behavior

3. Modify parameters to observe different behaviors:
   - Run with smaller variation in clock rates
   - Run with lower probability of internal events

## Next Steps

1. Complete the runs with the base configuration
2. Analyze logs and document observations
3. Run with modified parameters and compare results
4. Document findings and conclusions

## Observations (to be filled in after runs)

*Will be filled after conducting the experimental runs.*
