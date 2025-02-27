#!/usr/bin/env python3
import unittest
import os
import time
import socket
import queue
import threading
import tempfile
import random
from unittest.mock import patch, MagicMock, call
from virtual_machine import VirtualMachine

class TestVirtualMachine(unittest.TestCase):
    """Unit tests for the VirtualMachine class."""
    
    def setUp(self):
        """Set up test environment before each test."""
        # Use a temporary directory for log files
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "test_vm.log")
        
        # Set a fixed port for testing
        self.port = random.randint(50000, 60000)  # Use high ports for testing
        
        # Create VM with deterministic clock rate for testing
        with patch('random.randint', return_value=3):
            self.vm = VirtualMachine(
                machine_id=0,
                port=self.port,
                log_file=self.log_file
            )
    
    def tearDown(self):
        """Clean up after each test."""
        # Stop VM if it's running
        if hasattr(self, 'vm') and self.vm.running:
            self.vm.stop()
        
        # Remove temporary log file
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
    
    # Initialization Tests
    
    def test_clock_rate_initialization(self):
        """Test that VM initializes with a clock rate between 1-6 ticks per second."""
        # Create multiple VMs and check their clock rates
        for _ in range(10):
            vm = VirtualMachine(
                machine_id=0,
                port=self.port + 1,  # Use different port
                log_file=self.log_file
            )
            self.assertTrue(1 <= vm.clock_rate <= 6)
            vm.stop()
    
    def test_queue_initialization(self):
        """Verify that VM properly initializes both network and message queues."""
        self.assertIsInstance(self.vm.network_queue, queue.Queue)
        self.assertIsInstance(self.vm.message_queue, queue.Queue)
        self.assertTrue(self.vm.network_queue.empty())
        self.assertTrue(self.vm.message_queue.empty())
    
    def test_socket_creation(self):
        """Test that VM correctly creates a socket on the specified port."""
        self.assertIsInstance(self.vm.server_socket, socket.socket)
        # Verify the socket is bound to the correct port
        self.assertEqual(self.vm.server_socket.getsockname()[1], self.port)
        
    def test_logical_clock_initialization(self):
        """Verify the logical clock starts at 0."""
        self.assertEqual(self.vm.logical_clock, 0)
    
    # Connection Tests
    
    @patch('socket.socket')
    def test_peer_connection(self, mock_socket):
        """Test that VMs can connect to other VMs using socket connections."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Test connecting to peers
        peers = [(1, 10001), (2, 10002)]
        self.vm.connect_to_peers(peers)
        
        # Verify connection attempts
        self.assertEqual(mock_socket_instance.connect.call_count, 2)
        mock_socket_instance.connect.assert_has_calls([
            call(('localhost', 10001)),
            call(('localhost', 10002))
        ])
    
    # Message Handling Tests
    
    def test_network_queue_processing(self):
        """Test that messages in the network queue are moved to the message queue."""
        # Add a message to the network queue
        self.vm.network_queue.put("5")
        
        # Start the network processor thread
        self.vm.running = True
        thread = threading.Thread(target=self.vm.process_network_queue)
        thread.daemon = True
        thread.start()
        
        # Give it time to process
        time.sleep(0.1)
        
        # Check if message was moved to message queue
        self.assertEqual(self.vm.network_queue.qsize(), 0)
        self.assertEqual(self.vm.message_queue.qsize(), 1)
        self.assertEqual(self.vm.message_queue.get(), "5")
        
        # Clean up
        self.vm.running = False
        thread.join(0.1)
    
    # Logical Clock Tests
    
    def test_logical_clock_increment(self):
        """Test that the logical clock increments by 1 for internal events."""
        initial_clock = self.vm.logical_clock
        
        # Mock random.randint to return a value > 3 (internal event)
        with patch('random.randint', return_value=4):
            self.vm.run_clock_cycle()
        
        # Check that logical clock was incremented by 1
        self.assertEqual(self.vm.logical_clock, initial_clock + 1)
    
    def test_logical_clock_update_on_message_receipt(self):
        """Verify the logical clock updates correctly when receiving a message."""
        # Set initial logical clock
        self.vm.logical_clock = 5
        
        # Add a message with a higher logical clock to the message queue
        self.vm.message_queue.put("10")
        
        # Process the message
        self.vm.run_clock_cycle()
        
        # Check that logical clock updated correctly: max(5, 10) + 1 = 11
        self.assertEqual(self.vm.logical_clock, 11)
        
        # Test with a lower received clock value
        self.vm.logical_clock = 10
        self.vm.message_queue.put("5")
        self.vm.run_clock_cycle()
        
        # Check that logical clock updated correctly: max(10, 5) + 1 = 11
        self.assertEqual(self.vm.logical_clock, 11)
    
    # Event Generation Tests
    
    def test_random_event_generation(self):
        """Verify that a random event (1-10) is generated when there's no message."""
        event_counters = {
            'send_one': 0,
            'send_two': 0,
            'send_all': 0,
            'internal': 0
        }
        
        # Mock the send_message method to count calls
        original_send_message = self.vm.send_message
        self.vm.peer_sockets = {1: MagicMock(), 2: MagicMock()}
        
        def mock_send_message(peer_id):
            nonlocal event_counters
            original_send_message(peer_id)
        
        self.vm.send_message = mock_send_message
        
        # Run multiple clock cycles with different random values
        for i in range(1, 11):
            with patch('random.randint', return_value=i):
                with patch('random.choice', return_value=1):  # Mock for peer selection
                    self.vm.logical_clock = 0  # Reset logical clock
                    self.vm.run_clock_cycle()
                    
                    if i == 1:
                        event_counters['send_one'] += 1
                    elif i == 2:
                        event_counters['send_two'] += 1
                    elif i == 3:
                        event_counters['send_all'] += 1
                    else:
                        event_counters['internal'] += 1
        
        # Verify all event types were generated
        self.assertEqual(event_counters['send_one'], 1)
        self.assertEqual(event_counters['send_two'], 1)
        self.assertEqual(event_counters['send_all'], 1)
        self.assertEqual(event_counters['internal'], 7)
    
    @patch('random.choice')
    def test_send_event_type_1(self, mock_choice):
        """Test that when event type 1 occurs, a message is sent to one VM."""
        # Setup
        mock_choice.return_value = 1
        self.vm.peer_sockets = {1: MagicMock(), 2: MagicMock()}
        
        # Run clock cycle with event type 1
        with patch('random.randint', return_value=1):
            self.vm.run_clock_cycle()
        
        # Verify message was sent to one peer
        self.vm.peer_sockets[1].sendall.assert_called_once()
        self.vm.peer_sockets[2].sendall.assert_not_called()
    
    @patch('random.choice')
    def test_send_event_type_2(self, mock_choice):
        """Test that when event type 2 occurs, a message is sent to another VM."""
        # Setup
        mock_choice.return_value = 2
        self.vm.peer_sockets = {1: MagicMock(), 2: MagicMock()}
        
        # Run clock cycle with event type 2
        with patch('random.randint', return_value=2):
            self.vm.run_clock_cycle()
        
        # Verify message was sent to one peer
        self.vm.peer_sockets[2].sendall.assert_called_once()
    
    def test_send_event_type_3(self):
        """Test that when event type 3 occurs, messages are sent to all VMs."""
        # Setup
        self.vm.peer_sockets = {1: MagicMock(), 2: MagicMock()}
        
        # Run clock cycle with event type 3
        with patch('random.randint', return_value=3):
            self.vm.run_clock_cycle()
        
        # Verify messages were sent to all peers
        self.vm.peer_sockets[1].sendall.assert_called_once()
        self.vm.peer_sockets[2].sendall.assert_called_once()
    
    def test_internal_event(self):
        """Verify that when event type > 3 occurs, an internal event is processed."""
        # Run clock cycle with event type 4 (internal)
        with patch('random.randint', return_value=4):
            initial_clock = self.vm.logical_clock
            self.vm.run_clock_cycle()
        
        # Verify logical clock was incremented
        self.assertEqual(self.vm.logical_clock, initial_clock + 1)
        
        # Verify no messages were sent (would need to check logs or mock)
    
    # Logging Tests
    
    def test_log_message_generation(self):
        """Test that log messages are properly formatted."""
        # Test logging function
        with patch.object(self.vm.logger, 'info') as mock_info:
            self.vm.log("Test message")
            mock_info.assert_called_once()
            
            # Check log format contains logical clock
            log_msg = mock_info.call_args[0][0]
            self.assertIn(f"[LC:{self.vm.logical_clock}]", log_msg)
            self.assertIn("Test message", log_msg)
    
    # Shutdown Tests
    
    def test_vm_shutdown(self):
        """Verify that a VM can be properly shut down, closing all connections."""
        # Setup mock sockets
        mock_socket1 = MagicMock()
        mock_socket2 = MagicMock()
        self.vm.peer_sockets = {1: mock_socket1, 2: mock_socket2}
        
        # Start and then stop VM
        self.vm.start()
        time.sleep(0.1)  # Give time for threads to start
        self.vm.stop()
        
        # Verify sockets were closed
        mock_socket1.close.assert_called_once()
        mock_socket2.close.assert_called_once()
        
        # Verify running flag was set to False
        self.assertFalse(self.vm.running)


if __name__ == '__main__':
    unittest.main() 