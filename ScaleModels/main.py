#!/usr/bin/env python3
import sys
import time
import argparse
from virtual_machine import VirtualMachine

def main():
    """
    Main function to set up and run the distributed system model.
    """
    parser = argparse.ArgumentParser(description='Run a distributed system model with logical clocks')
    parser.add_argument('--runtime', type=int, default=60, 
                        help='Runtime in seconds (default: 60)')
    parser.add_argument('--vm-count', type=int, default=3, 
                        help='Number of virtual machines (default: 3)')
    parser.add_argument('--base-port', type=int, default=10000, 
                        help='Base port number (default: 10000)')
    parser.add_argument('--log_dir', type=str, default=1, 
                        help='Directory to save log files (default: logs)')
    args = parser.parse_args()
    # Create virtual machines
    vms = []
    for i in range(args.vm_count):
        port = args.base_port + i
        vm = VirtualMachine(
            machine_id=i,
            port=port,
            log_file=f"logs/{args.log_dir}/vm_{i}.log"
        )
        vms.append(vm)
        print(f"Created VM {i} on port {port}")
    
    # Connect each VM to all other VMs
    for i, vm in enumerate(vms):
        other_vms = [(j, args.base_port + j) for j in range(args.vm_count) if j != i]
        assert len(other_vms) == args.vm_count - 1, "Each VM must connect to all other VMs"
        vm.connect_to_peers(other_vms)
    
    # Start all virtual machines
    for vm in vms:
        vm.start()
    
    # Wait for the specified runtime
    try:
        print(f"System running for {args.runtime} seconds...")
        time.sleep(args.runtime)
    except KeyboardInterrupt:
        print("Interrupted by user. Shutting down...")
    
    # Stop all virtual machines
    for vm in vms:
        vm.stop()
    
    print("System shutdown complete.")

if __name__ == "__main__":
    main() 