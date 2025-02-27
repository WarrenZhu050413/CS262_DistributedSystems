#!/usr/bin/env python3
import os
import re
import sys
import glob
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime

def parse_log_file(file_path):
    """
    Parse a VM log file into a structured format.
    
    Returns:
        dict: A dictionary containing log entries parsed into structured data
    """
    data = {
        'timestamp': [],
        'logical_clock': [],
        'event_type': [],
        'queue_length': [],
        'message': []
    }
    
    with open(file_path, 'r') as f:
        for line in f:
            # Parse timestamp
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
            if not timestamp_match:
                continue
            
            timestamp_str = timestamp_match.group(1)
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
            
            # Parse logical clock
            lc_match = re.search(r'\[LC:(\d+)\]', line)
            if not lc_match:
                continue
            
            logical_clock = int(lc_match.group(1))
            
            # Parse message content and event type
            if "Received message" in line:
                event_type = "receive"
                queue_match = re.search(r'Queue length: (\d+)', line)
                queue_length = int(queue_match.group(1)) if queue_match else 0
            elif "Sent message to VM" in line:
                event_type = "send_one"
                queue_length = 0
            elif "Sent messages to all VMs" in line:
                event_type = "send_all"
                queue_length = 0
            elif "Internal event" in line:
                event_type = "internal"
                queue_length = 0
            else:
                event_type = "other"
                queue_length = 0
            
            # Store data
            data['timestamp'].append(timestamp)
            data['logical_clock'].append(logical_clock)
            data['event_type'].append(event_type)
            data['queue_length'].append(queue_length)
            data['message'].append(line.strip())
    
    assert len(data['timestamp']) > 0, f"No valid log entries found in {file_path}"
    return data

def analyze_logs(log_dir):
    """
    Analyze all log files in the given directory.
    
    Args:
        log_dir (str): Directory containing log files
    """
    log_files = glob.glob(os.path.join(log_dir, "vm_*.log"))
    assert len(log_files) > 0, f"No log files found in {log_dir}"
    
    vm_data = {}
    
    # Parse all log files
    for log_file in log_files:
        vm_id = os.path.basename(log_file).replace("vm_", "").replace(".log", "")
        vm_data[vm_id] = parse_log_file(log_file)
    
    # Convert to DataFrames
    dfs = {}
    for vm_id, data in vm_data.items():
        df = pd.DataFrame(data)
        df['vm_id'] = vm_id
        dfs[vm_id] = df
    
    # Combine all data
    all_data = pd.concat(dfs.values())
    
    # Sort by timestamp
    all_data = all_data.sort_values('timestamp')
    
    # Analysis
    print(f"Total events: {len(all_data)}")
    print("\nEvents by type:")
    print(all_data['event_type'].value_counts())
    
    print("\nEvents by VM:")
    print(all_data['vm_id'].value_counts())
    
    print("\nQueue length statistics:")
    queue_stats = all_data[all_data['event_type'] == 'receive']['queue_length'].describe()
    print(queue_stats)
    
    # Calculate logical clock drift
    print("\nLogical clock rates:")
    for vm_id, df in dfs.items():
        duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        lc_range = df['logical_clock'].max() - df['logical_clock'].min()
        rate = lc_range / duration if duration > 0 else 0
        print(f"VM {vm_id}: {rate:.2f} ticks/second")
    
    # Plot logical clocks over time
    plt.figure(figsize=(12, 6))
    for vm_id, df in dfs.items():
        plt.plot(df['timestamp'], df['logical_clock'], label=f"VM {vm_id}")
    
    plt.xlabel('Time')
    plt.ylabel('Logical Clock Value')
    plt.title('Logical Clock Values Over Time')
    plt.legend()
    plt.grid(True)
    
    # Save the plot
    plot_path = os.path.join(log_dir, "logical_clock_plot.png")
    plt.savefig(plot_path)
    print(f"\nPlot saved to {plot_path}")
    
    # Plot queue lengths
    plt.figure(figsize=(12, 6))
    for vm_id, df in dfs.items():
        receive_events = df[df['event_type'] == 'receive']
        if not receive_events.empty:
            plt.plot(receive_events['timestamp'], receive_events['queue_length'], 
                     label=f"VM {vm_id}")
    
    plt.xlabel('Time')
    plt.ylabel('Queue Length')
    plt.title('Message Queue Length Over Time')
    plt.legend()
    plt.grid(True)
    
    # Save the plot
    queue_plot_path = os.path.join(log_dir, "queue_length_plot.png")
    plt.savefig(queue_plot_path)
    print(f"Plot saved to {queue_plot_path}")

def main():
    """Main function to run the log analysis"""
    if len(sys.argv) > 1:
        log_dir = sys.argv[1]
    else:
        log_dir = "logs"
    
    if not os.path.exists(log_dir):
        print(f"Error: Log directory '{log_dir}' does not exist.")
        return 1
    
    analyze_logs(log_dir)
    return 0

if __name__ == "__main__":
    sys.exit(main()) 