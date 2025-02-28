#!/usr/bin/env python3
import os
import re
import sys
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
from scipy.stats import linregress

def parse_log_file(file_path, verbose=False):
    """
    Parse a VM log file into a structured format.
    
    Args:
        file_path: Path to the log file
        verbose: Whether to print verbose output for debugging
        
    Returns:
        dict: A dictionary containing log entries parsed into structured data
    """
    # Initialize data structure
    data = {
        'timestamp': [],
        'system_time': [],
        'machine_id': [],
        'logical_clock': [],
        'event_type': [],
        'queue_length': [],
        'message': []
    }
    
    # Check if file exists and has content
    if not os.path.exists(file_path):
        print(f"Warning: File does not exist: {file_path}")
        return data
    
    if os.path.getsize(file_path) == 0:
        print(f"Warning: File is empty: {file_path}")
        return data
    
    # For debugging
    if verbose:
        print(f"Parsing log file: {file_path}")
    
    line_count = 0
    parsed_count = 0
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line_count += 1
            
            # Try different timestamp patterns
            # Pattern 1: YYYY-MM-DD HH:MM:SS.f
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\w+)', line)
            if not timestamp_match:
                # Pattern 2: YYYY-MM-DD HH:MM:SS,millisec
                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
            
            if not timestamp_match:
                if verbose and line_num <= 5:  # Only show first few problematic lines
                    print(f"Line {line_num} failed timestamp match: {line.strip()}")
                continue
            
            timestamp_str = timestamp_match.group(1)
            
            # Handle different timestamp formats
            try:
                if ',' in timestamp_str:  # Format with comma for milliseconds
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                else:  # Format with dot for fraction of seconds
                    # Handle the .f format by replacing it with .0
                    timestamp_str = re.sub(r'\.\w+', '.0', timestamp_str)
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError as e:
                if verbose:
                    print(f"Failed to parse timestamp {timestamp_str}: {e}")
                continue
            
            # Parse machine ID
            machine_id_match = re.search(r'M(\d+)', line)
            if machine_id_match:
                machine_id = int(machine_id_match.group(1))
            else:
                if verbose and line_num <= 5:
                    print(f"Line {line_num} failed machine ID match: {line.strip()}")
                machine_id = -1  # Default if not found
            
            # Parse logical clock
            lc_match = re.search(r'\[LC:(\d+)\]', line)
            if not lc_match:
                if verbose and line_num <= 5:
                    print(f"Line {line_num} failed logical clock match: {line.strip()}")
                continue
            
            logical_clock = int(lc_match.group(1))
            
            # Parse clock rate
            clock_rate_match = re.search(r'clock rate (\d+)', line)
            if clock_rate_match:
                clock_rate = int(clock_rate_match.group(1))
                # Store clock rate in separate text file for later reference
                with open(os.path.join(os.path.dirname(file_path), f"vm_{machine_id}_rate.txt"), 'w') as rate_file:
                    rate_file.write(str(clock_rate))
            
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
            data['system_time'].append(timestamp.timestamp())
            data['machine_id'].append(machine_id)
            data['logical_clock'].append(logical_clock)
            data['event_type'].append(event_type)
            data['queue_length'].append(queue_length)
            data['message'].append(line.strip())
            
            parsed_count += 1
    
    if verbose:
        print(f"Parsed {parsed_count} log entries from {line_count} lines in {file_path}")
    
    if len(data['timestamp']) == 0:
        print(f"Warning: No valid log entries found in {file_path}")
        print(f"Please check if the log format matches the expected format.")
        # Don't raise an assertion error, just return empty data
        # This allows the program to continue with other files
    
    return data

def get_machine_rate(log_dir, machine_id):
    """Get the clock rate for a specific machine from the log directory"""
    rate_file = os.path.join(log_dir, f"vm_{machine_id}_rate.txt")
    if os.path.exists(rate_file):
        with open(rate_file, 'r') as f:
            return int(f.read().strip())
    
    # If rate file doesn't exist, try to extract from log file
    log_file = os.path.join(log_dir, f"vm_{machine_id}.log")
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            for line in f:
                if "clock rate" in line:
                    rate_match = re.search(r'clock rate (\d+)', line)
                    if rate_match:
                        rate = int(rate_match.group(1))
                        return rate
    
    # Default if not found
    return 0

def process_logs_to_dataframe(log_dir, verbose=False):
    """
    Process all logs in a directory into a pandas DataFrame and save to CSV.
    
    Args:
        log_dir: Directory containing log files
        verbose: Whether to print verbose output for debugging
        
    Returns:
        DataFrame: Combined data from all log files
    """
    log_files = glob.glob(os.path.join(log_dir, "vm_*.log"))
    if len(log_files) == 0:
        print(f"Warning: No log files found in {log_dir}")
        return pd.DataFrame()
    
    vm_data = {}
    clock_rates = {}
    
    # Parse all log files
    for log_file in log_files:
        vm_id_match = re.search(r'vm_(\d+)\.log', os.path.basename(log_file))
        if vm_id_match:
            vm_id = int(vm_id_match.group(1))
            if verbose:
                print(f"Processing log file for VM {vm_id}: {log_file}")
            
            vm_data[vm_id] = parse_log_file(log_file, verbose=verbose)
            
            # Get clock rate for this VM
            clock_rate = get_machine_rate(log_dir, vm_id)
            clock_rates[vm_id] = clock_rate
            
            if verbose:
                print(f"VM {vm_id} has clock rate: {clock_rate}")
    
    # Check if we have any data
    if not vm_data:
        print(f"Error: No valid data could be parsed from logs in {log_dir}")
        return pd.DataFrame()
    
    # Convert to DataFrames
    dfs = {}
    for vm_id, data in vm_data.items():
        if not data['timestamp']:
            print(f"Warning: No valid entries for VM {vm_id}")
            continue
            
        df = pd.DataFrame(data)
        df['vm_id'] = vm_id
        df['clock_rate'] = clock_rates.get(vm_id, 0)
        dfs[vm_id] = df
    
    # Check if we have any DataFrames
    if not dfs:
        print(f"Error: Could not create any DataFrames from logs in {log_dir}")
        return pd.DataFrame()
    
    # Combine all data
    all_data = pd.concat(dfs.values())
    
    # Sort by timestamp
    all_data = all_data.sort_values('timestamp')
    
    # Calculate time since start (in seconds)
    start_time = all_data['system_time'].min()
    all_data['time_since_start'] = all_data['system_time'] - start_time
    
    # Calculate logical clock jumps (difference between consecutive logical clock values)
    for vm_id in vm_data.keys():
        if vm_id not in dfs:
            continue
            
        vm_df = all_data[all_data['vm_id'] == vm_id].copy()
        vm_df = vm_df.sort_values('timestamp')
        vm_df['prev_lc'] = vm_df['logical_clock'].shift(1)
        vm_df['lc_jump'] = vm_df['logical_clock'] - vm_df['prev_lc']
        # Replace the rows in the all_data DataFrame
        all_data.loc[vm_df.index, 'prev_lc'] = vm_df['prev_lc']
        all_data.loc[vm_df.index, 'lc_jump'] = vm_df['lc_jump']
    
    # Clean up NaN values (first row of each VM won't have a previous value)
    all_data['lc_jump'] = all_data['lc_jump'].fillna(0)
    all_data['prev_lc'] = all_data['prev_lc'].fillna(0)
    
    # Save to CSV
    csv_path = os.path.join(log_dir, "parsed_logs.csv")
    all_data.to_csv(csv_path, index=False)
    if verbose or len(all_data) > 0:
        print(f"Saved log data to {csv_path}")
    
    return all_data

def analyze_logical_clock_jumps(df, output_dir):
    """
    Analyze the jumps in logical clock values.
    
    Args:
        df: DataFrame with log data
        output_dir: Directory to save output plots
    """
    print("\n--- Analyzing Logical Clock Jumps ---")
    
    # Filter out rows with valid jumps
    jump_df = df[df['lc_jump'] > 0].copy()
    
    # a) Histogram of jumps
    plt.figure(figsize=(12, 8))
    plt.hist(jump_df['lc_jump'], bins=20, color='skyblue', edgecolor='black')
    plt.title('Histogram of Logical Clock Jumps (All VMs)')
    plt.xlabel('Jump Size')
    plt.ylabel('Frequency')
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'jumps_histogram_all.png'))
    plt.close()
    
    # Histograms by clock rate
    plt.figure(figsize=(15, 10))
    rates = sorted(jump_df['clock_rate'].unique())
    colors = sns.color_palette('husl', len(rates))
    
    for i, rate in enumerate(rates):
        rate_df = jump_df[jump_df['clock_rate'] == rate]
        if not rate_df.empty:
            plt.hist(rate_df['lc_jump'], bins=20, alpha=0.6, 
                     label=f'Rate {rate} (n={len(rate_df)})',
                     color=colors[i], edgecolor='black')
    
    plt.title('Histogram of Logical Clock Jumps by Clock Rate')
    plt.xlabel('Jump Size')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'jumps_histogram_by_rate.png'))
    plt.close()
    
    # b) Line graph of sum of jumps over time
    time_intervals = np.arange(0, df['time_since_start'].max(), 0.5)
    jump_sums = []
    
    for start in time_intervals:
        end = start + 0.5
        interval_df = jump_df[(jump_df['time_since_start'] >= start) & 
                              (jump_df['time_since_start'] < end)]
        jump_sums.append(interval_df['lc_jump'].sum())
    
    plt.figure(figsize=(12, 6))
    plt.plot(time_intervals, jump_sums, marker='o', markersize=4, linestyle='-')
    plt.title('Sum of Logical Clock Jumps Over Time')
    plt.xlabel('Time Since Start (seconds)')
    plt.ylabel('Sum of Jumps')
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'jumps_sum_over_time.png'))
    plt.close()
    
    # c) Linear regression of jumps vs clock rate
    rates = []
    jump_sums_by_rate = []
    
    for rate in sorted(jump_df['clock_rate'].unique()):
        rate_df = jump_df[jump_df['clock_rate'] == rate]
        rates.append(rate)
        jump_sums_by_rate.append(rate_df['lc_jump'].sum())
    
    rates = np.array(rates).reshape(-1, 1)
    jump_sums_by_rate = np.array(jump_sums_by_rate)
    
    plt.figure(figsize=(10, 6))
    plt.scatter(rates, jump_sums_by_rate, color='blue', s=100)
    
    # Linear regression
    if len(rates) > 1:
        # Linear model
        linear_reg = LinearRegression()
        linear_reg.fit(rates, jump_sums_by_rate)
        linear_pred = linear_reg.predict(rates)
        plt.plot(rates, linear_pred, color='red', linewidth=2, label=f'Linear (R²={linear_reg.score(rates, jump_sums_by_rate):.3f})')
        
        # Quadratic model
        poly = PolynomialFeatures(degree=2)
        rates_poly = poly.fit_transform(rates)
        poly_reg = LinearRegression()
        poly_reg.fit(rates_poly, jump_sums_by_rate)
        sorted_rates = np.sort(rates, axis=0)
        sorted_rates_poly = poly.transform(sorted_rates)
        plt.plot(sorted_rates, poly_reg.predict(sorted_rates_poly), color='green', linewidth=2, 
                label=f'Quadratic (R²={poly_reg.score(rates_poly, jump_sums_by_rate):.3f})')
        
        # Cubic model
        poly = PolynomialFeatures(degree=3)
        rates_poly = poly.fit_transform(rates)
        poly_reg = LinearRegression()
        poly_reg.fit(rates_poly, jump_sums_by_rate)
        sorted_rates_poly = poly.transform(sorted_rates)
        plt.plot(sorted_rates, poly_reg.predict(sorted_rates_poly), color='purple', linewidth=2, 
                label=f'Cubic (R²={poly_reg.score(rates_poly, jump_sums_by_rate):.3f})')
    
    plt.title('Sum of Logical Clock Jumps vs Clock Rate')
    plt.xlabel('Clock Rate (ticks/second)')
    plt.ylabel('Sum of Jumps')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'jumps_vs_rate_regression.png'))
    plt.close()

def analyze_logical_clock_drift(df, output_dir):
    """
    Analyze the drift in logical clock values between machines.
    
    Args:
        df: DataFrame with log data
        output_dir: Directory to save output plots
    """
    print("\n--- Analyzing Logical Clock Drift ---")
    
    # Get list of all VMs
    vm_ids = sorted(df['vm_id'].unique())
    
    # a) Plot logical clock values over time for each VM
    # Create time intervals of 3 seconds
    interval = 3
    max_time = df['time_since_start'].max()
    time_points = np.arange(0, max_time, interval)
    
    logical_clocks = {vm_id: [] for vm_id in vm_ids}
    clock_rates = {vm_id: df[df['vm_id'] == vm_id]['clock_rate'].iloc[0] for vm_id in vm_ids}
    
    for t in time_points:
        for vm_id in vm_ids:
            # Get the last logical clock value before this time point
            vm_df = df[(df['vm_id'] == vm_id) & (df['time_since_start'] <= t)]
            if not vm_df.empty:
                logical_clocks[vm_id].append(vm_df['logical_clock'].iloc[-1])
            else:
                logical_clocks[vm_id].append(0)
    
    plt.figure(figsize=(12, 6))
    colors = sns.color_palette('husl', len(vm_ids))
    
    for i, vm_id in enumerate(vm_ids):
        if len(logical_clocks[vm_id]) == len(time_points):
            plt.plot(time_points, logical_clocks[vm_id], marker='o', 
                     label=f'VM {vm_id} (Rate {clock_rates[vm_id]})',
                     color=colors[i], linewidth=2)
    
    plt.title('Logical Clock Values Over Time (3-second intervals)')
    plt.xlabel('Time Since Start (seconds)')
    plt.ylabel('Logical Clock Value')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'logical_clock_values_over_time.png'))
    plt.close()
    
    # b) Plot sum of absolute differences between logical clocks
    diff_sums = []
    
    for t_idx, t in enumerate(time_points):
        diff_sum = 0
        pairs_count = 0
        
        for i, vm_id1 in enumerate(vm_ids):
            for vm_id2 in enumerate(vm_ids[i+1:]):
                if (t_idx < len(logical_clocks[vm_id1]) and 
                    t_idx < len(logical_clocks[vm_id2[1]])):
                    diff_sum += abs(logical_clocks[vm_id1][t_idx] - 
                                     logical_clocks[vm_id2[1]][t_idx])
                    pairs_count += 1
        
        if pairs_count > 0:
            diff_sums.append(diff_sum)
        else:
            diff_sums.append(0)
    
    plt.figure(figsize=(12, 6))
    plt.plot(time_points, diff_sums, marker='o', color='red', linewidth=2)
    plt.title('Sum of Absolute Differences Between Logical Clocks')
    plt.xlabel('Time Since Start (seconds)')
    plt.ylabel('Sum of Absolute Differences')
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'logical_clock_differences.png'))
    plt.close()
    
    # c) Regression of clock rate variance vs logical clock variance
    # This is applicable when analyzing multiple runs
    
def analyze_queue_lengths(df, output_dir):
    """
    Analyze message queue lengths and their relationship to clock rates.
    
    Args:
        df: DataFrame with log data
        output_dir: Directory to save output plots
    """
    print("\n--- Analyzing Queue Lengths ---")
    
    # Filter to only include receive events (which have queue length)
    queue_df = df[df['event_type'] == 'receive'].copy()
    
    # Get list of all VMs
    vm_ids = sorted(df['vm_id'].unique())
    clock_rates = {vm_id: df[df['vm_id'] == vm_id]['clock_rate'].iloc[0] for vm_id in vm_ids}
    
    # a) Line graph of queue lengths over time
    interval = 0.5
    max_time = df['time_since_start'].max()
    time_points = np.arange(0, max_time, interval)
    
    queue_lengths = {vm_id: [] for vm_id in vm_ids}
    
    for t in time_points:
        t_end = t + interval
        for vm_id in vm_ids:
            # Get the average queue length in this interval
            vm_interval_df = queue_df[(queue_df['vm_id'] == vm_id) & 
                                      (queue_df['time_since_start'] >= t) &
                                      (queue_df['time_since_start'] < t_end)]
            if not vm_interval_df.empty:
                queue_lengths[vm_id].append(vm_interval_df['queue_length'].mean())
            else:
                queue_lengths[vm_id].append(0)
    
    plt.figure(figsize=(12, 6))
    colors = sns.color_palette('husl', len(vm_ids))
    
    for i, vm_id in enumerate(vm_ids):
        plt.plot(time_points, queue_lengths[vm_id], 
                 label=f'VM {vm_id} (Rate {clock_rates[vm_id]})',
                 color=colors[i], linewidth=2)
    
    plt.title('Message Queue Lengths Over Time')
    plt.xlabel('Time Since Start (seconds)')
    plt.ylabel('Queue Length')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'queue_lengths_over_time.png'))
    plt.close()
    
    # b) Line graph of logical clock differences over time
    lc_diffs = {vm_id: [] for vm_id in vm_ids}
    
    for vm_id in vm_ids:
        vm_df = df[df['vm_id'] == vm_id].copy()
        vm_df = vm_df.sort_values('timestamp')
        
        # Calculate differences between consecutive logical clock values
        for t in time_points:
            t_end = t + interval
            interval_df = vm_df[(vm_df['time_since_start'] >= t) & 
                                (vm_df['time_since_start'] < t_end)]
            
            if len(interval_df) > 1:
                # Calculate average difference in this interval
                diffs = interval_df['logical_clock'].diff().dropna()
                lc_diffs[vm_id].append(diffs.mean())
            else:
                lc_diffs[vm_id].append(0)
    
    plt.figure(figsize=(12, 6))
    
    for i, vm_id in enumerate(vm_ids):
        plt.plot(time_points[:len(lc_diffs[vm_id])], lc_diffs[vm_id], 
                 label=f'VM {vm_id} (Rate {clock_rates[vm_id]})',
                 color=colors[i], linewidth=2)
    
    plt.title('Logical Clock Consecutive Differences')
    plt.xlabel('Time Since Start (seconds)')
    plt.ylabel('Average Difference')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(output_dir, 'logical_clock_consecutive_diffs.png'))
    plt.close()

def perform_cross_run_analysis(run_dirs, output_dir):
    """
    Perform analysis across multiple runs.
    
    Args:
        run_dirs: List of directories containing runs to analyze
        output_dir: Directory to save output plots
    """
    print("\n--- Performing Cross-Run Analysis ---")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # b) Error bars for jumps across runs
    time_points = np.arange(0, 60, 0.5)  # Assuming 60 second runs
    jump_sums_by_run = []
    
    for run_dir in run_dirs:
        log_data_path = os.path.join(run_dir, "parsed_logs.csv")
        if os.path.exists(log_data_path):
            run_df = pd.read_csv(log_data_path)
            
            # Convert string timestamp to datetime
            run_df['timestamp'] = pd.to_datetime(run_df['timestamp'])
            
            jump_sums = []
            for start in time_points:
                end = start + 0.5
                interval_df = run_df[(run_df['time_since_start'] >= start) & 
                                    (run_df['time_since_start'] < end)]
                jump_sums.append(interval_df['lc_jump'].sum())
            
            jump_sums_by_run.append(jump_sums)
    
    # Calculate mean and variance
    if jump_sums_by_run:
        jump_sums_array = np.array(jump_sums_by_run)
        jump_means = np.mean(jump_sums_array, axis=0)
        jump_stds = np.std(jump_sums_array, axis=0)
        
        plt.figure(figsize=(12, 6))
        plt.errorbar(time_points[:len(jump_means)], jump_means, yerr=jump_stds, 
                    marker='o', markersize=4, capsize=5)
        plt.title('Sum of Logical Clock Jumps Over Time (Across Runs)')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Sum of Jumps')
        plt.grid(True, alpha=0.3)
        plt.savefig(os.path.join(output_dir, 'cross_run_jumps_with_error_bars.png'))
        plt.close()
    
    # c) Regression of clock rate variance vs logical clock variance
    rate_variances = []
    lc_variances = []
    
    for run_dir in run_dirs:
        log_data_path = os.path.join(run_dir, "parsed_logs.csv")
        if os.path.exists(log_data_path):
            run_df = pd.read_csv(log_data_path)
            
            # Get clock rate variance
            vm_rates = []
            for vm_id in run_df['vm_id'].unique():
                rate = run_df[run_df['vm_id'] == vm_id]['clock_rate'].iloc[0]
                vm_rates.append(rate)
            
            rate_var = np.var(vm_rates)
            rate_variances.append(rate_var)
            
            # Get logical clock variance at end of run
            lc_values = []
            for vm_id in run_df['vm_id'].unique():
                vm_df = run_df[run_df['vm_id'] == vm_id]
                if not vm_df.empty:
                    last_lc = vm_df.sort_values('time_since_start')['logical_clock'].iloc[-1]
                    lc_values.append(last_lc)
            
            lc_var = np.var(lc_values)
            lc_variances.append(lc_var)
    
    if len(rate_variances) > 1:
        plt.figure(figsize=(10, 6))
        plt.scatter(rate_variances, lc_variances, color='blue', s=100)
        
        # Linear regression
        slope, intercept, r_value, p_value, std_err = linregress(rate_variances, lc_variances)
        x_line = np.linspace(min(rate_variances), max(rate_variances), 100)
        y_line = slope * x_line + intercept
        
        # Calculate R-squared - avoid using the ** operator
        r_squared = r_value * r_value
        
        plt.plot(x_line, y_line, color='red', linewidth=2, 
                label=f'Linear Regression\ny = {slope:.2f}x + {intercept:.2f}\nR² = {r_squared:.3f}')
        
        plt.title('Clock Rate Variance vs Logical Clock Variance')
        plt.xlabel('Clock Rate Variance')
        plt.ylabel('Logical Clock Value Variance')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(os.path.join(output_dir, 'rate_variance_vs_lc_variance.png'))
        plt.close()

def analyze_all_runs(base_dir="./logs", output_dir="./Analysis/plots", verbose=False):
    """
    Analyze all runs in the specified base directory.
    
    Args:
        base_dir: Base directory containing run directories
        output_dir: Directory to save output plots
        verbose: Whether to print verbose output for debugging
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    run_dirs = []
    
    # Check for numbered directories (0, 1, 2, 3, 4)
    for i in range(5):
        run_dir = os.path.join(base_dir, str(i))
        if os.path.isdir(run_dir):
            run_dirs.append(run_dir)
    
    # If no numbered directories found, treat base_dir as a single run
    if not run_dirs and os.path.isdir(base_dir):
        run_dirs = [base_dir]
    
    if not run_dirs:
        print(f"No valid run directories found in {base_dir}")
        return
    
    # Process each run
    for run_dir in run_dirs:
        print(f"\n=== Processing run in {run_dir} ===")
        run_output_dir = os.path.join(output_dir, os.path.basename(run_dir))
        os.makedirs(run_output_dir, exist_ok=True)
        
        # Process logs to DataFrame
        df = process_logs_to_dataframe(run_dir, verbose=verbose)
        
        if len(df) == 0:
            print(f"Skipping analysis for run directory {run_dir} due to no data")
            continue
        
        # Perform analyses
        try:
            analyze_logical_clock_jumps(df, run_output_dir)
            analyze_logical_clock_drift(df, run_output_dir)
            analyze_queue_lengths(df, run_output_dir)
        except Exception as e:
            print(f"Error during analysis for {run_dir}: {e}")
    
    # Perform cross-run analysis if multiple runs exist
    if len(run_dirs) > 1:
        try:
            perform_cross_run_analysis(run_dirs, output_dir)
        except Exception as e:
            print(f"Error during cross-run analysis: {e}")

def main():
    """Main function to run the log analysis"""
    # Add verbose/debug flag
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    if verbose:
        print("Running in verbose mode")
    
    # Parse command line arguments
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        base_dir = sys.argv[1]
    else:
        base_dir = "./logs"
    
    output_dir = "./Analysis/plots"
    
    if not os.path.exists(base_dir):
        print(f"Error: Log directory '{base_dir}' does not exist.")
        return 1
    
    analyze_all_runs(base_dir, output_dir, verbose=verbose)
    return 0

if __name__ == "__main__":
    sys.exit(main())