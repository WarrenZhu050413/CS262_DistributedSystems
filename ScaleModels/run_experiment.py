#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import argparse
import shutil

def create_run_directory(base_dir, run_id):
    """Create a directory for a specific run"""
    # Assert inputs are valid
    assert isinstance(base_dir, str), "base_dir must be a string"
    assert isinstance(run_id, (int, str)), "run_id must be an integer or string"
    assert os.path.exists(os.path.dirname(os.path.abspath(base_dir))), f"Parent directory for {base_dir} does not exist"
    
    run_dir = os.path.join(base_dir, str(run_id))
    os.makedirs(run_dir, exist_ok=True)
    
    # Verify directory was created
    assert os.path.exists(run_dir), f"Failed to create run directory: {run_dir}"
    return run_dir

def run_experiment(runtime, vm_count, base_port, log_dir, run_id):
    """Run a single experiment with the specified parameters"""
    # Validate input parameters
    assert isinstance(runtime, int) and runtime > 0, "Runtime must be a positive integer"
    assert isinstance(vm_count, int) and vm_count > 0, "VM count must be a positive integer"
    assert isinstance(base_port, int) and 1024 <= base_port <= 65535, "Base port must be a valid port number (1024-65535)"
    assert isinstance(log_dir, str), "Log directory must be a string"
    assert isinstance(run_id, int) and run_id >= 0, "Run ID must be a non-negative integer"
    
    print(f"\n=== Starting Run {run_id} ===")
    print(f"Runtime: {runtime} seconds")
    print(f"VM Count: {vm_count}")
    print(f"Base Port: {base_port}")
    print(f"Log Directory: {log_dir}")
    
    # Create the log directory for this run
    run_dir = create_run_directory(log_dir, run_id)
    assert os.path.exists(run_dir), f"Failed to create or access run directory: {run_dir}"
    
    # Build the command to run the main.py script
    cmd = [
        "python", "main.py",
        "--runtime", str(runtime),
        "--vm-count", str(vm_count),
        "--base-port", str(base_port)
    ]
    
    # Verify main.py exists
    assert os.path.exists("main.py"), "main.py not found in current directory"
    
    # Set the LOGS_DIR environment variable
    env = os.environ.copy()
    env["LOGS_DIR"] = run_dir
    
    # Run the experiment
    try:
        # Start the process
        print(f"Running command: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, env=env)
        
        # Wait for the process to complete
        proc.wait()
        
        if proc.returncode == 0:
            print(f"Run {run_id} completed successfully.")
        else:
            print(f"Run {run_id} failed with return code {proc.returncode}.")
            return False
        
    except KeyboardInterrupt:
        print("\nExperiment interrupted by user. Stopping...")
        proc.terminate()
        return False
    except Exception as e:
        print(f"Error running experiment: {e}")
        return False
    
    # Verify logs were created
    log_files = [f for f in os.listdir(run_dir) if f.endswith(".log")]
    assert len(log_files) > 0, f"No log files were created in {run_dir}"
    
    return True

def update_virtual_machine(internal_event_prob=None, clock_rate_range=None):
    """
    Update virtual_machine.py with modified parameters if specified.
    
    Args:
        internal_event_prob: New probability for internal events (out of 10)
        clock_rate_range: New range for clock rates as (min, max)
    
    Returns:
        bool: Whether the update was successful
    """
    # Validate parameters if provided
    if internal_event_prob is not None:
        assert isinstance(internal_event_prob, int), "internal_event_prob must be an integer"
        assert 1 <= internal_event_prob <= 10, "internal_event_prob must be between 1 and 10"
    
    if clock_rate_range is not None:
        assert isinstance(clock_rate_range, tuple) and len(clock_rate_range) == 2, "clock_rate_range must be a tuple of (min, max)"
        min_rate, max_rate = clock_rate_range
        assert isinstance(min_rate, int) and isinstance(max_rate, int), "Clock rates must be integers"
        assert 1 <= min_rate <= max_rate, "Min rate must be between 1 and max_rate"
        assert max_rate >= min_rate, "Max rate must be greater than or equal to min_rate"
    
    vm_file = "virtual_machine.py"
    backup_file = f"{vm_file}.bak"
    
    # Check that virtual_machine.py exists
    assert os.path.exists(vm_file), f"{vm_file} not found in current directory"
    
    # Create a backup of the original file
    shutil.copy2(vm_file, backup_file)
    assert os.path.exists(backup_file), f"Failed to create backup file: {backup_file}"
    
    try:
        with open(vm_file, "r") as f:
            content = f.read()
        
        original_content = content
        
        # Update internal event probability if specified
        if internal_event_prob is not None:
            # This assumes random.randint(1, 10) is used with > 3 for internal events
            # We need to adjust the comparison value based on the new probability
            comparison_value = 10 - internal_event_prob
            if comparison_value < 1:
                comparison_value = 1
            
            # Replace the comparison in the code
            content = content.replace(
                "if event_type == 1:",
                f"if event_type <= {comparison_value}:"
            )
            
            print(f"Updated internal event probability: {internal_event_prob}/10")
        
        # Update clock rate range if specified
        if clock_rate_range is not None:
            min_rate, max_rate = clock_rate_range
            
            # Replace the random.randint call for clock rate
            content = content.replace(
                "self.clock_rate = random.randint(1, 6)",
                f"self.clock_rate = random.randint({min_rate}, {max_rate})"
            )
            
            # Update the assertion
            content = content.replace(
                "assert 1 <= self.clock_rate <= 6",
                f"assert {min_rate} <= self.clock_rate <= {max_rate}"
            )
            
            print(f"Updated clock rate range: {min_rate}-{max_rate}")
        
        # Only write if we actually changed something
        assert content != original_content, "No changes were made to the file"
        
        # Write the modified content back to the file
        with open(vm_file, "w") as f:
            f.write(content)
        
        # Verify the file was updated
        with open(vm_file, "r") as f:
            new_content = f.read()
        assert new_content == content, "File content does not match expected modifications"
        
        return True
    except Exception as e:
        print(f"Error updating virtual_machine.py: {e}")
        # Restore from backup
        shutil.copy2(backup_file, vm_file)
        return False

def restore_virtual_machine():
    """Restore virtual_machine.py from backup"""
    vm_file = "virtual_machine.py"
    backup_file = f"{vm_file}.bak"
    
    if os.path.exists(backup_file):
        # Check if the original file exists
        assert os.path.exists(vm_file), f"{vm_file} not found, cannot restore"
        
        shutil.copy2(backup_file, vm_file)
        # Verify the file was restored
        assert os.path.getsize(vm_file) > 0, f"Restored {vm_file} is empty"
        
        os.remove(backup_file)
        # Verify backup was removed
        assert not os.path.exists(backup_file), f"Failed to remove backup file: {backup_file}"
        
        print("Restored virtual_machine.py from backup.")

def run_analysis(log_dir):
    """Run the analysis scripts on the collected data"""
    # Validate input
    assert isinstance(log_dir, str), "Log directory must be a string"
    
    print("\n=== Running Analysis ===")
    
    # Ensure the log directory exists
    assert os.path.exists(log_dir), f"Error: Log directory '{log_dir}' does not exist."
    
    # Check that analysis scripts exist
    analyze_logs_script = "Analysis/analyze_logs.py"
    analyze_metrics_script = "Analysis/analyze_specific_metrics.py"
    
    assert os.path.exists(analyze_logs_script), f"{analyze_logs_script} not found"
    assert os.path.exists(analyze_metrics_script), f"{analyze_metrics_script} not found"
    
    # First, parse logs to create CSV files
    run_dirs_exist = False
    for run_id in range(5):  # Assumes we did 5 runs
        run_dir = os.path.join(log_dir, str(run_id))
        if os.path.exists(run_dir):
            run_dirs_exist = True
            cmd = ["python", analyze_logs_script, run_dir]
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd)
            assert result.returncode == 0, f"analyze_logs.py failed with return code {result.returncode}"
    
    assert run_dirs_exist, f"No run directories found in {log_dir}"
    
    # Now, run the specific metrics analysis
    cmd = ["python", analyze_metrics_script, log_dir]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    assert result.returncode == 0, f"analyze_specific_metrics.py failed with return code {result.returncode}"
    
    return True

def main():
    """Main function to run the experiments"""
    parser = argparse.ArgumentParser(description='Run multiple distributed system experiments')
    parser.add_argument('--runs', type=int, default=5, 
                        help='Number of runs to perform (default: 5)')
    parser.add_argument('--runtime', type=int, default=60, 
                        help='Runtime for each experiment in seconds (default: 60)')
    parser.add_argument('--vm-count', type=int, default=3, 
                        help='Number of virtual machines for each run (default: 3)')
    parser.add_argument('--base-port', type=int, default=10000, 
                        help='Base port number (default: 10000)')
    parser.add_argument('--log-dir', type=str, default='logs', 
                        help='Directory to store logs (default: logs)')
    parser.add_argument('--internal-prob', type=int, 
                        help='New probability for internal events (out of 10)')
    parser.add_argument('--min-rate', type=int, 
                        help='Minimum clock rate')
    parser.add_argument('--max-rate', type=int, 
                        help='Maximum clock rate')
    parser.add_argument('--analyze-only', action='store_true',
                        help='Only run analysis on existing logs')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.runs is not None:
        assert args.runs > 0, "Number of runs must be positive"
    
    if args.runtime is not None:
        assert args.runtime > 0, "Runtime must be positive"
    
    if args.vm_count is not None:
        assert args.vm_count > 0, "VM count must be positive"
    
    if args.base_port is not None:
        assert 1024 <= args.base_port <= 65535, "Base port must be between 1024 and 65535"
    
    if args.internal_prob is not None:
        assert 1 <= args.internal_prob <= 10, "Internal probability must be between 1 and 10"
    
    if args.min_rate is not None and args.max_rate is not None:
        assert 1 <= args.min_rate <= args.max_rate, "Min rate must be between 1 and max rate"
    
    # Create the base log directory
    os.makedirs(args.log_dir, exist_ok=True)
    assert os.path.exists(args.log_dir), f"Failed to create log directory: {args.log_dir}"
    
    if args.analyze_only:
        run_analysis(args.log_dir)
        return 0
    
    try:
        # Update virtual_machine.py if parameters specified
        clock_rate_range = None
        if args.min_rate is not None and args.max_rate is not None:
            clock_rate_range = (args.min_rate, args.max_rate)
        
        if args.internal_prob is not None or clock_rate_range is not None:
            success = update_virtual_machine(args.internal_prob, clock_rate_range)
            assert success, "Failed to update virtual_machine.py"
        
        # Run experiments
        for run_id in range(args.runs):
            success = run_experiment(
                args.runtime, 
                args.vm_count, 
                args.base_port + (run_id * 100),  # Use different port ranges for each run
                args.log_dir,
                run_id
            )
            
            if not success:
                print(f"Experiment run {run_id} failed. Stopping...")
                break
            
            # Wait briefly between runs
            time.sleep(2)
        
        # Run analysis
        run_analysis(args.log_dir)
        
    finally:
        # Restore virtual_machine.py if we modified it
        restore_virtual_machine()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 