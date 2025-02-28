#!/usr/bin/env python3
import os
import time
import random
import socket
import threading
import queue
import logging
from datetime import datetime

class VirtualMachine:
    """
    A virtual machine in the distributed system model.
    Each VM has its own clock rate, logical clock, and communication capabilities.
    """
    
    def __init__(self, machine_id, port, log_file):
        """
        Initialize a virtual machine.
        
        Args:
            machine_id (int): The ID of this virtual machine
            port (int): The port this VM will listen on
            log_file (str): Path to the log file for this VM
        """
        self.machine_id = machine_id
        self.port = port
        self.log_file = log_file
        # Remove existing log file if it exists
        if os.path.exists(log_file):
            os.remove(log_file)

        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        # Set up logging - FIXED to use a FileHandler for each VM
        self.logger = logging.getLogger(f"VM_{machine_id}")
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers if any
        if self.logger.handlers:
            for handler in self.logger.handlers:
                self.logger.removeHandler(handler)
                
        # Create file handler for this VM
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S.%f')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        # Initialize logical clock
        self.logical_clock = 0
        
        # Set random clock rate (1-6 ticks per second)
        self.clock_rate = random.randint(1, 6)
        self.clock_interval = 1.0 / self.clock_rate
        assert 1 <= self.clock_rate <= 6, "Clock rate must be between 1 and 6"
        
        # Initialize queues
        self.network_queue = queue.Queue()  # Always on, listening for incoming messages
        self.message_queue = queue.Queue()  # Processed at clock rate
        
        # Set up socket for listening
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)
        
        # Track connections to other VMs
        self.peer_sockets = {}  # {machine_id: socket}
        
        # Control flags
        self.running = False
        self.threads = []
        
        # Log initialization
        self.log(f"Initialized with clock rate {self.clock_rate} ticks/second")
        
    def log(self, message):
        """Log a message with timestamp and logical clock value"""
        system_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self.logger.info(f"M{self.machine_id} [LC:{self.logical_clock}] {message}")
        
    def connect_to_peers(self, peers):
        """
        Connect to other virtual machines.
        
        Args:
            peers (list): List of (machine_id, port) tuples for other VMs
        """
        for peer_id, peer_port in peers:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect(('localhost', peer_port))
                self.peer_sockets[peer_id] = peer_socket
                self.log(f"Connected to VM {peer_id} on port {peer_port}")
            except ConnectionRefusedError:
                self.log(f"Failed to connect to VM {peer_id} on port {peer_port}")
        
        assert len(self.peer_sockets) == len(peers), "Failed to connect to all peers"
    
    def network_queue_listens(self):
        """Listen for incoming messages on the server socket"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                self.threads.append(client_handler)
            except OSError:
                # Socket closed
                break
    
    def handle_client(self, client_socket, addr):
        """Handle messages from a connected client"""
        while self.running:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                # Put received message in network queue
                message = data.decode('utf-8')
                self.network_queue.put(message)
            except:
                break
        
        client_socket.close()
    
    def process_network_queue(self):
        """Move messages from network queue to message queue"""
        while not self.network_queue.empty():
            message = self.network_queue.get()
            self.message_queue.put(message)

    def run_clock_cycle(self):
        """Execute one clock cycle according to the VM's logic"""
        # Process network queue
        self.process_network_queue()
        # Process a message if available
        if not self.message_queue.empty():
            message = self.message_queue.get()
            received_clock = int(message)
            
            # Update logical clock (Lamport's rule)
            self.logical_clock = max(self.logical_clock, received_clock) + 1
            assert self.logical_clock > received_clock, "Logical clock must advance when receiving a message"
            
            # Log the message receipt
            queue_length = self.message_queue.qsize()
            self.log(f"Received message. Queue length: {queue_length}")
            
        else:
            # No message to process, generate a random event
            event_type = random.randint(1, 10)
            
            # Increment logical clock for any event
            self.logical_clock += 1
            
            if event_type == 1:
                # Send to the first peer
                peer_id = list(self.peer_sockets.keys())[0]
                self.send_message(peer_id)
                self.log(f"Sent message to VM {peer_id}")
            
            elif event_type == 2:
                # Send to the second peer
                peer_id = list(self.peer_sockets.keys())[1]
                self.send_message(peer_id)
                self.log(f"Sent message to VM {peer_id}")
            
            elif event_type == 3:
                # Send to all other VMs
                for peer_id in self.peer_sockets:
                    self.send_message(peer_id)
                self.log(f"Sent messages to all VMs")
            else:
                # Internal event
                self.log("Internal event")
    
    def send_message(self, peer_id):
        """Send the current logical clock value to a peer VM"""
        try:
            message = str(self.logical_clock)
            self.peer_sockets[peer_id].sendall(message.encode('utf-8')) # Sendall to ensure the message is sent
        except:
            self.log(f"Failed to send message to VM {peer_id}")
    
    def run_clock(self):
        """Run the clock at the specified rate"""
        while self.running:
            start_time = time.time()
            
            # Run one clock cycle
            self.run_clock_cycle()
            
            # Sleep for the remainder of the clock interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.clock_interval - elapsed)
            time.sleep(sleep_time)
    
    def start(self):
        """Start the virtual machine"""
        self.running = True
        
        # Start the listener thread
        network_processor = threading.Thread(target=self.network_queue_listens)
        network_processor.daemon = True
        network_processor.start()
        self.threads.append(network_processor)
        
        # Start the clock thread
        clock_thread = threading.Thread(target=self.run_clock)
        clock_thread.daemon = True
        clock_thread.start()
        self.threads.append(clock_thread)
        
        self.log(f"Started VM {self.machine_id} with clock rate {self.clock_rate}")
    
    def stop(self):
        """Stop the virtual machine"""
        self.running = False
        
        # Close all connections
        for peer_id, sock in self.peer_sockets.items():
            sock.close()
        
        # Close server socket
        self.server_socket.close()
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(1.0)  # Wait with timeout
        
        self.log(f"Stopped VM {self.machine_id}") 