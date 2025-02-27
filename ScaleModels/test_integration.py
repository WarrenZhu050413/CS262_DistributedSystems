#!/usr/bin/env python3
import unittest
import os
import time
import shutil
import tempfile
import glob
from virtual_machine import VirtualMachine

class TestDistributedSystem(unittest.TestCase):
    """Integration tests for the distributed system model."""
    
    def setUp(self):
        """Set up test environment before each test."""
        # Create temporary directory for logs
        self.test_dir = tempfile.mkdtemp()
        self.log_dir = os.path.join(self.test_dir, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Base port for VMs
        self.base_port = 60000
        
        # Create VMs
        self.vms = []
    
    def tearDown(self):
        """Clean up after each test."""
        # Stop all VMs
        for vm in self.vms:
            if vm.running:
                vm.stop()
        
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_two_vm_communication(self):
        """Test basic communication between two VMs."""
        # Create two VMs
        vm1 = VirtualMachine(
            machine_id=1,
            port=self.base_port + 1,
            log_file=os.path.join(self.log_dir, "vm_1.log")
        )
        vm2 = VirtualMachine(
            machine_id=2,
            port=self.base_port + 2,
            log_file=os.path.join(self.log_dir, "vm_2.log")
        )
        
        self.vms.append(vm1)
        self.vms.append(vm2)
        
        # Connect VMs to each other
        vm1.connect_to_peers([(2, self.base_port + 2)])
        vm2.connect_to_peers([(1, self.base_port + 1)])
        
        # Start VMs
        vm1.start()
        vm2.start()
        
        # Run for a short time
        time.sleep(5)
        
        # Stop VMs
        vm1.stop()
        vm2.stop()
        
        # Check that log files were created
        self.assertTrue(os.path.exists(os.path.join(self.log_dir, "vm_1.log")))
        self.assertTrue(os.path.exists(os.path.join(self.log_dir, "vm_2.log")))
        
        # Verify log file has content
        with open(os.path.join(self.log_dir, "vm_1.log"), 'r') as f:
            content = f.read()
            self.assertGreater(len(content), 0)
    
    def test_three_vm_system(self):
        """Test a system with three VMs."""
        # Create three VMs
        vm_count = 3
        for i in range(1, vm_count + 1):
            vm = VirtualMachine(
                machine_id=i,
                port=self.base_port + i,
                log_file=os.path.join(self.log_dir, f"vm_{i}.log")
            )
            self.vms.append(vm)
            
            # Log initial clock rate for verification
            print(f"VM {i} clock rate: {vm.clock_rate}")
        
        # Connect each VM to all others
        for i, vm in enumerate(self.vms):
            other_vms = [(j+1, self.base_port + j + 1) for j in range(vm_count) if j+1 != vm.machine_id]
            vm.connect_to_peers(other_vms)
        
        # Start all VMs
        for vm in self.vms:
            vm.start()
        
        # Run for a short time
        time.sleep(10)
        
        # Stop all VMs
        for vm in self.vms:
            vm.stop()
        
        # Check that log files were created for all VMs
        for i in range(1, vm_count + 1):
            log_file = os.path.join(self.log_dir, f"vm_{i}.log")
            self.assertTrue(os.path.exists(log_file))
            
            # Check log content
            with open(log_file, 'r') as f:
                content = f.read()
                print(f"VM {i} log size: {len(content)} bytes")
                
                # Check for evidence of different event types
                self.assertIn("Started VM", content)
                self.assertIn("Logical clock", content)
                
                # Assertions about log content that should be true
                # regardless of random behavior
                self.assertGreater(len(content), 100)  # Log should have substantial content
    
    def test_logical_clock_behavior(self):
        """Test that logical clocks behave according to Lamport's rules."""
        # Create two VMs with fixed clock rates for deterministic testing
        vm1 = VirtualMachine(
            machine_id=1,
            port=self.base_port + 1,
            log_file=os.path.join(self.log_dir, "vm_1.log")
        )
        # Manually set clock rate to ensure vm1 is slower than vm2
        vm1.clock_rate = 1
        vm1.clock_interval = 1.0
        
        vm2 = VirtualMachine(
            machine_id=2,
            port=self.base_port + 2,
            log_file=os.path.join(self.log_dir, "vm_2.log")
        )
        # Manually set clock rate to ensure vm2 is faster than vm1
        vm2.clock_rate = 6
        vm2.clock_interval = 1.0 / 6
        
        self.vms.append(vm1)
        self.vms.append(vm2)
        
        # Connect VMs to each other
        vm1.connect_to_peers([(2, self.base_port + 2)])
        vm2.connect_to_peers([(1, self.base_port + 1)])
        
        # Start VMs
        vm1.start()
        vm2.start()
        
        # Run for a short time
        time.sleep(5)
        
        # Stop VMs
        vm1.stop()
        vm2.stop()
        
        # Analyze logs to verify logical clock behavior
        # This would normally be done with analyze_logs.py
        # Here we'll just check basic expectations
        
        # Read log files
        with open(os.path.join(self.log_dir, "vm_1.log"), 'r') as f:
            vm1_log = f.readlines()
        
        with open(os.path.join(self.log_dir, "vm_2.log"), 'r') as f:
            vm2_log = f.readlines()
        
        # Assert some basic expectations
        self.assertGreater(len(vm1_log), 5)
        self.assertGreater(len(vm2_log), 5)
        
        # The faster VM (vm2) should have more log entries
        self.assertGreater(len(vm2_log), len(vm1_log))
        
        # Print sample log entries for manual verification
        print("\nSample VM1 log entries:")
        for line in vm1_log[:5]:
            print(line.strip())
        
        print("\nSample VM2 log entries:")
        for line in vm2_log[:5]:
            print(line.strip())
        
        # Note: A more comprehensive check would parse logs and check 
        # logical clock values directly


if __name__ == '__main__':
    unittest.main() 