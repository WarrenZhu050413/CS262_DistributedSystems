#!/usr/bin/env python3
import os
import sys
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures

def analyze_logical_clock_jumps(runs_data, output_dir):
    """
    Analyze the jumps in logical clock values as requested.
    
    Args:
        runs_data: Dictionary mapping run IDs to DataFrames
        output_dir: Directory to save output plots
    """
    # Validate input parameters
    assert isinstance(runs_data, dict), "runs_data must be a dictionary"
    assert len(runs_data) > 0, "No run data provided for analysis"
    assert isinstance(output_dir, str), "output_dir must be a string"
    
    # Validate DataFrame structure for each run
    required_columns = ['lc_jump', 'time_since_start', 'clock_rate', 'vm_id', 'logical_clock']
    for run_id, df in runs_data.items():
        assert isinstance(df, pd.DataFrame), f"Run {run_id} data must be a DataFrame"
        for col in required_columns:
            assert col in df.columns, f"Column '{col}' missing from run {run_id} DataFrame"
    
    print("\n--- Analyzing Logical Clock Jumps ---")
    os.makedirs(output_dir, exist_ok=True)
    assert os.path.exists(output_dir), f"Failed to create output directory: {output_dir}"
    
    # 1.a) Histograms of jump values
    # Aggregate histogram for all runs
    all_jumps = []
    for run_id, df in runs_data.items():
        jumps = df[df['lc_jump'] > 0]['lc_jump'].values
        all_jumps.extend(jumps)
    
    # Only create histograms if we have jumps
    if len(all_jumps) > 0:
        plt.figure(figsize=(12, 8))
        plt.hist(all_jumps, bins=20, color='skyblue', edgecolor='black')
        plt.title('Histogram of Logical Clock Jumps (All Runs, All VMs)')
        plt.xlabel('Jump Size')
        plt.ylabel('Frequency')
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, 'jumps_histogram_all_runs.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
    else:
        print("Warning: No logical clock jumps found in the data")
    
    # Histograms by clock rate
    all_jumps_by_rate = {}
    for run_id, df in runs_data.items():
        for rate in df['clock_rate'].unique():
            if rate not in all_jumps_by_rate:
                all_jumps_by_rate[rate] = []
            
            rate_jumps = df[(df['clock_rate'] == rate) & (df['lc_jump'] > 0)]['lc_jump'].values
            all_jumps_by_rate[rate].extend(rate_jumps)
    
    # Only create histograms if we have jumps for at least one rate
    if any(len(jumps) > 0 for jumps in all_jumps_by_rate.values()):
        plt.figure(figsize=(15, 10))
        colors = sns.color_palette('husl', len(all_jumps_by_rate))
        
        for i, (rate, jumps) in enumerate(sorted(all_jumps_by_rate.items())):
            if jumps:
                plt.hist(jumps, bins=20, alpha=0.6, 
                         label=f'Rate {rate} (n={len(jumps)})',
                         color=colors[i], edgecolor='black')
        
        plt.title('Histogram of Logical Clock Jumps by Clock Rate (All Runs)')
        plt.xlabel('Jump Size')
        plt.ylabel('Frequency')
        plt.legend()
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, 'jumps_histogram_by_rate_all_runs.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
    
    # 1.b) Line graph of jumps over time with error bars
    # Validate run duration for time intervals
    max_time = max(df['time_since_start'].max() for df in runs_data.values())
    assert max_time > 0, "No valid time data found in runs"
    
    time_intervals = np.arange(0, max_time, 0.5)  # Dynamic based on actual max time
    assert len(time_intervals) > 0, "No valid time intervals could be created"
    
    jumps_by_run_and_time = {}
    
    for run_id, df in runs_data.items():
        jumps_by_time = []
        for start in time_intervals:
            end = start + 0.5
            interval_df = df[(df['time_since_start'] >= start) & 
                            (df['time_since_start'] < end) &
                            (df['lc_jump'] > 0)]
            jumps_by_time.append(interval_df['lc_jump'].sum())
        
        assert len(jumps_by_time) == len(time_intervals), f"Length mismatch in jumps_by_time for run {run_id}"
        jumps_by_run_and_time[run_id] = jumps_by_time
        
        # Plot for this individual run
        plt.figure(figsize=(12, 6))
        plt.plot(time_intervals, jumps_by_time, marker='o', markersize=4, linestyle='-')
        plt.title(f'Sum of Logical Clock Jumps Over Time (Run {run_id})')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Sum of Jumps')
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, f'jumps_sum_over_time_run_{run_id}.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
    
    # Error bar plot across all runs
    if len(jumps_by_run_and_time) > 1:
        jumps_array = []
        for run_id in sorted(jumps_by_run_and_time.keys()):
            jumps_array.append(jumps_by_run_and_time[run_id])
        
        jumps_array = np.array(jumps_array)
        assert jumps_array.shape[1] == len(time_intervals), "Shape mismatch in jumps_array"
        
        jumps_mean = np.mean(jumps_array, axis=0)
        jumps_std = np.std(jumps_array, axis=0)
        
        plt.figure(figsize=(12, 6))
        plt.errorbar(time_intervals, jumps_mean, yerr=jumps_std, marker='o', 
                   markersize=4, capsize=5, ecolor='red', elinewidth=1)
        plt.title('Sum of Logical Clock Jumps Over Time (All Runs)')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Sum of Jumps')
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, 'jumps_sum_over_time_with_error_bars.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
    
    # 1.c) Linear regression of jumps vs clock rate
    rates = []
    jump_sums = []
    
    for run_id, df in runs_data.items():
        for rate in sorted(df['clock_rate'].unique()):
            rate_df = df[(df['clock_rate'] == rate) & (df['lc_jump'] > 0)]
            rates.append(rate)
            jump_sums.append(rate_df['lc_jump'].sum())
    
    # Only proceed with regression if we have data points
    if len(rates) > 0:
        rates = np.array(rates).reshape(-1, 1)
        jump_sums = np.array(jump_sums)
        assert len(rates) == len(jump_sums), "Length mismatch between rates and jump_sums"
        
        plt.figure(figsize=(10, 6))
        plt.scatter(rates, jump_sums, color='blue', s=100)
        
        # Linear regression
        if len(rates) > 1:
            # Linear model (degree 1)
            linear_reg = LinearRegression()
            linear_reg.fit(rates, jump_sums)
            linear_pred = linear_reg.predict(rates)
            plt.plot(rates, linear_pred, color='red', linewidth=2, 
                    label=f'Linear (R²={linear_reg.score(rates, jump_sums):.3f})')
            
            # Try higher degree polynomials if we have enough data points
            if len(rates) > 3:
                # Try several polynomial degrees
                for degree in range(2, min(4, len(rates))):
                    poly = PolynomialFeatures(degree=degree)
                    rates_poly = poly.fit_transform(rates)
                    
                    poly_reg = LinearRegression()
                    poly_reg.fit(rates_poly, jump_sums)
                    
                    # Generate points for a smooth curve
                    rates_range = np.linspace(rates.min(), rates.max(), 100).reshape(-1, 1)
                    rates_range_poly = poly.transform(rates_range)
                    
                    plt.plot(rates_range, poly_reg.predict(rates_range_poly), 
                            linewidth=2, 
                            label=f'Degree {degree} (R²={poly_reg.score(rates_poly, jump_sums):.3f})')
        
        plt.title('Sum of Logical Clock Jumps vs Clock Rate')
        plt.xlabel('Clock Rate (ticks/second)')
        plt.ylabel('Sum of Jumps')
        plt.legend()
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, 'jumps_vs_rate_regression.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"

def analyze_logical_clock_drift(runs_data, output_dir):
    """
    Analyze drift in logical clock values between machines.
    
    Args:
        runs_data: Dictionary mapping run IDs to DataFrames
        output_dir: Directory to save output plots
    """
    # Validate input parameters
    assert isinstance(runs_data, dict), "runs_data must be a dictionary"
    assert len(runs_data) > 0, "No run data provided for analysis"
    assert isinstance(output_dir, str), "output_dir must be a string"
    
    # Validate DataFrame structure for each run
    required_columns = ['time_since_start', 'clock_rate', 'vm_id', 'logical_clock']
    for run_id, df in runs_data.items():
        assert isinstance(df, pd.DataFrame), f"Run {run_id} data must be a DataFrame"
        for col in required_columns:
            assert col in df.columns, f"Column '{col}' missing from run {run_id} DataFrame"
    
    print("\n--- Analyzing Logical Clock Drift ---")
    os.makedirs(output_dir, exist_ok=True)
    assert os.path.exists(output_dir), f"Failed to create output directory: {output_dir}"
    
    # 2.a) Plot logical clock values at 3-second intervals
    for run_id, df in runs_data.items():
        # Get list of all VMs in this run
        vm_ids = sorted(df['vm_id'].unique())
        assert len(vm_ids) > 0, f"No VM IDs found in run {run_id}"
        
        clock_rates = {vm_id: df[df['vm_id'] == vm_id]['clock_rate'].iloc[0] 
                      for vm_id in vm_ids}
        assert len(clock_rates) == len(vm_ids), "Missing clock rates for some VMs"
        
        # Create time intervals of 3 seconds
        interval = 3
        max_time = df['time_since_start'].max()
        assert max_time > 0, f"No valid time data found in run {run_id}"
        
        time_points = np.arange(0, max_time, interval)
        assert len(time_points) > 0, f"No valid time points could be created for run {run_id}"
        
        logical_clocks = {vm_id: [] for vm_id in vm_ids}
        
        for t in time_points:
            for vm_id in vm_ids:
                # Get the last logical clock value before or at this time point
                vm_df = df[(df['vm_id'] == vm_id) & (df['time_since_start'] <= t)]
                if not vm_df.empty:
                    lc_value = vm_df.sort_values('time_since_start').iloc[-1]['logical_clock']
                    logical_clocks[vm_id].append(lc_value)
                else:
                    logical_clocks[vm_id].append(0)
        
        # Verify we have data for all VMs
        for vm_id in vm_ids:
            assert len(logical_clocks[vm_id]) > 0, f"No logical clock values for VM {vm_id} in run {run_id}"
            assert len(logical_clocks[vm_id]) == len(time_points), f"Length mismatch in logical_clocks for VM {vm_id} in run {run_id}"
        
        plt.figure(figsize=(12, 6))
        colors = sns.color_palette('husl', len(vm_ids))
        
        for i, vm_id in enumerate(vm_ids):
            plt.plot(time_points[:len(logical_clocks[vm_id])], logical_clocks[vm_id], 
                    marker='o', label=f'VM {vm_id} (Rate {clock_rates[vm_id]})',
                    color=colors[i], linewidth=2)
        
        plt.title(f'Logical Clock Values Over Time (Run {run_id}, 3-second intervals)')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Logical Clock Value')
        plt.legend()
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, f'logical_clock_values_run_{run_id}.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
        
        # 2.b) Plot the sum of absolute differences between logical clocks
        diff_sums = []
        
        for t_idx, t in enumerate(time_points):
            diff_sum = 0
            pairs_count = 0
            
            for i, vm_id1 in enumerate(vm_ids):
                for j, vm_id2 in enumerate(vm_ids):
                    if i < j:  # Only consider each pair once
                        if (t_idx < len(logical_clocks[vm_id1]) and 
                            t_idx < len(logical_clocks[vm_id2])):
                            diff_sum += abs(logical_clocks[vm_id1][t_idx] - 
                                           logical_clocks[vm_id2][t_idx])
                            pairs_count += 1
            
            if pairs_count > 0:
                diff_sums.append(diff_sum)
            else:
                diff_sums.append(0)
        
        assert len(diff_sums) == len(time_points), f"Length mismatch in diff_sums for run {run_id}"
        
        plt.figure(figsize=(12, 6))
        plt.plot(time_points[:len(diff_sums)], diff_sums, marker='o', 
                color='red', linewidth=2)
        plt.title(f'Sum of Absolute Differences Between Logical Clocks (Run {run_id})')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Sum of Absolute Differences')
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, f'logical_clock_abs_diff_run_{run_id}.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
    
    # 2.c) Linear regression of clock rate variance vs logical clock variance
    if len(runs_data) > 1:
        rate_vars = []
        lc_vars = []
        
        for run_id, df in runs_data.items():
            # Calculate clock rate variance for this run
            vm_clock_rates = [df[df['vm_id'] == vm_id]['clock_rate'].iloc[0] 
                             for vm_id in df['vm_id'].unique()]
            rate_vars.append(np.var(vm_clock_rates))
            
            # Calculate logical clock variance at the end
            end_time = df['time_since_start'].max() - 1  # 1 second before the end
            end_lc_values = []
            
            for vm_id in df['vm_id'].unique():
                vm_df = df[(df['vm_id'] == vm_id) & (df['time_since_start'] <= end_time)]
                if not vm_df.empty:
                    end_lc_values.append(vm_df.sort_values('time_since_start').iloc[-1]['logical_clock'])
            
            if len(end_lc_values) > 1:
                lc_vars.append(np.var(end_lc_values))
            else:
                lc_vars.append(0)
        
        # Only create the plot if we have valid data points
        if len(rate_vars) > 0 and len(lc_vars) > 0:
            assert len(rate_vars) == len(lc_vars), "Length mismatch between rate_vars and lc_vars"
            
            # Convert to numpy arrays for regression
            rate_vars = np.array(rate_vars).reshape(-1, 1)
            lc_vars = np.array(lc_vars)
            
            plt.figure(figsize=(10, 6))
            plt.scatter(rate_vars, lc_vars, color='blue', s=100)
            
            # Linear regression if we have at least 2 points
            if len(rate_vars) > 1:
                linear_reg = LinearRegression()
                linear_reg.fit(rate_vars, lc_vars)
                linear_pred = linear_reg.predict(rate_vars)
                
                plt.plot(rate_vars, linear_pred, color='red', linewidth=2,
                        label=f'Linear (R²={linear_reg.score(rate_vars, lc_vars):.3f})')
            
            plt.title('Logical Clock Variance vs Clock Rate Variance')
            plt.xlabel('Clock Rate Variance')
            plt.ylabel('Logical Clock Variance')
            if len(rate_vars) > 1:
                plt.legend()
            plt.grid(True, alpha=0.3)
            output_file = os.path.join(output_dir, 'clock_variance_regression.png')
            plt.savefig(output_file)
            plt.close()
            assert os.path.exists(output_file), f"Failed to save output file: {output_file}"

def analyze_queue_lengths(runs_data, output_dir):
    """
    Analyze message queue lengths in the system.
    
    Args:
        runs_data: Dictionary mapping run IDs to DataFrames
        output_dir: Directory to save output plots
    """
    # Validate input parameters
    assert isinstance(runs_data, dict), "runs_data must be a dictionary"
    assert len(runs_data) > 0, "No run data provided for analysis"
    assert isinstance(output_dir, str), "output_dir must be a string"
    
    # Validate DataFrame structure for each run
    required_columns = ['time_since_start', 'clock_rate', 'vm_id', 'logical_clock', 'queue_length']
    for run_id, df in runs_data.items():
        assert isinstance(df, pd.DataFrame), f"Run {run_id} data must be a DataFrame"
        for col in required_columns:
            assert col in df.columns, f"Column '{col}' missing from run {run_id} DataFrame"
    
    print("\n--- Analyzing Queue Lengths ---")
    os.makedirs(output_dir, exist_ok=True)
    assert os.path.exists(output_dir), f"Failed to create output directory: {output_dir}"
    
    # 3.a) Queue lengths over time
    for run_id, df in runs_data.items():
        # Get list of all VMs in this run
        vm_ids = sorted(df['vm_id'].unique())
        assert len(vm_ids) > 0, f"No VM IDs found in run {run_id}"
        
        clock_rates = {vm_id: df[df['vm_id'] == vm_id]['clock_rate'].iloc[0] 
                      for vm_id in vm_ids}
        
        plt.figure(figsize=(12, 6))
        colors = sns.color_palette('husl', len(vm_ids))
        
        for i, vm_id in enumerate(vm_ids):
            vm_df = df[df['vm_id'] == vm_id].sort_values('time_since_start')
            if not vm_df.empty:
                plt.plot(vm_df['time_since_start'], vm_df['queue_length'], 
                        marker='.', label=f'VM {vm_id} (Rate {clock_rates[vm_id]})',
                        color=colors[i], linewidth=1)
        
        plt.title(f'Message Queue Lengths Over Time (Run {run_id})')
        plt.xlabel('Time Since Start (seconds)')
        plt.ylabel('Queue Length')
        plt.legend()
        plt.grid(True, alpha=0.3)
        output_file = os.path.join(output_dir, f'queue_lengths_run_{run_id}.png')
        plt.savefig(output_file)
        plt.close()
        assert os.path.exists(output_file), f"Failed to save output file: {output_file}"
        
        # 3.b) Queue length vs clock rate
        if len(vm_ids) > 1:
            avg_queue_lengths = []
            vm_rates = []
            
            for vm_id in vm_ids:
                vm_df = df[df['vm_id'] == vm_id]
                if not vm_df.empty:
                    avg_queue_lengths.append(vm_df['queue_length'].mean())
                    vm_rates.append(clock_rates[vm_id])
            
            if len(avg_queue_lengths) > 1:
                assert len(avg_queue_lengths) == len(vm_rates), "Length mismatch between avg_queue_lengths and vm_rates"
                
                plt.figure(figsize=(10, 6))
                plt.scatter(vm_rates, avg_queue_lengths, color='blue', s=100)
                
                if len(vm_rates) > 1:
                    # Convert to numpy arrays for regression
                    vm_rates = np.array(vm_rates).reshape(-1, 1)
                    avg_queue_lengths = np.array(avg_queue_lengths)
                    
                    # Linear regression
                    linear_reg = LinearRegression()
                    linear_reg.fit(vm_rates, avg_queue_lengths)
                    
                    # Generate points for a smooth line
                    rate_range = np.linspace(min(vm_rates), max(vm_rates), 100).reshape(-1, 1)
                    queue_pred = linear_reg.predict(rate_range)
                    
                    plt.plot(rate_range, queue_pred, color='red', linewidth=2,
                            label=f'Linear (R²={linear_reg.score(vm_rates, avg_queue_lengths):.3f})')
                
                plt.title(f'Average Queue Length vs Clock Rate (Run {run_id})')
                plt.xlabel('Clock Rate (ticks/second)')
                plt.ylabel('Average Queue Length')
                if len(vm_rates) > 1:
                    plt.legend()
                plt.grid(True, alpha=0.3)
                output_file = os.path.join(output_dir, f'queue_length_vs_rate_run_{run_id}.png')
                plt.savefig(output_file)
                plt.close()
                assert os.path.exists(output_file), f"Failed to save output file: {output_file}"

def load_run_data(base_dir="./logs"):
    """
    Load data from all runs in the specified directory.
    
    Args:
        base_dir: Base directory containing run directories
    
    Returns:
        Dictionary mapping run IDs to DataFrames
    """
    # Validate input
    assert isinstance(base_dir, str), "base_dir must be a string"
    assert os.path.exists(base_dir), f"Base directory does not exist: {base_dir}"
    
    runs_data = {}
    run_dirs = glob.glob(os.path.join(base_dir, "*"))
    
    if not run_dirs:
        print(f"Warning: No run directories found in {base_dir}")
        return runs_data
    
    for run_dir in run_dirs:
        try:
            run_id = int(os.path.basename(run_dir))
        except ValueError:
            # Skip directories that don't have numeric names
            continue
        
        csv_file = os.path.join(run_dir, "parsed_logs.csv")
        if os.path.exists(csv_file):
            try:
                df = pd.read_csv(csv_file)
                
                # Check if the DataFrame has the required columns
                required_columns = ['time_since_start', 'vm_id', 'logical_clock', 'clock_rate']
                if all(col in df.columns for col in required_columns):
                    # Calculate lc_jump (logical clock jumps)
                    df = df.sort_values(['vm_id', 'time_since_start'])
                    
                    # Initialize column if it doesn't exist
                    if 'lc_jump' not in df.columns:
                        df['lc_jump'] = 0
                    
                    # Calculate jumps for each VM
                    for vm_id in df['vm_id'].unique():
                        vm_df = df[df['vm_id'] == vm_id].copy()
                        vm_df['lc_jump'] = vm_df['logical_clock'].diff()
                        vm_df.loc[vm_df['lc_jump'] <= 1, 'lc_jump'] = 0  # Not a jump if ≤ 1
                        df.loc[df['vm_id'] == vm_id, 'lc_jump'] = vm_df['lc_jump']
                    
                    runs_data[run_id] = df
                    print(f"Loaded data for Run {run_id}")
                else:
                    missing = [col for col in required_columns if col not in df.columns]
                    print(f"Warning: Run {run_id} CSV missing required columns: {missing}")
            except Exception as e:
                print(f"Error loading CSV for Run {run_id}: {e}")
        else:
            print(f"Warning: No parsed_logs.csv found in {run_dir}")
    
    # Make sure we have at least one valid run
    assert len(runs_data) > 0, f"No valid run data found in {base_dir}"
    
    return runs_data

def main():
    """Main function to run the analysis"""
    # Parse command line arguments
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = "./logs"
    
    # Validate the base directory
    assert os.path.exists(base_dir), f"Base directory does not exist: {base_dir}"
    
    print(f"Analyzing logs in: {base_dir}")
    
    # Create output directories
    results_dir = "Analysis/results"
    jumps_dir = os.path.join(results_dir, "jumps")
    drift_dir = os.path.join(results_dir, "drift")
    queue_dir = os.path.join(results_dir, "queue")
    
    # Load the data
    runs_data = load_run_data(base_dir)
    assert runs_data, f"No data was loaded from {base_dir}"
    
    # Run the analyses
    analyze_logical_clock_jumps(runs_data, jumps_dir)
    analyze_logical_clock_drift(runs_data, drift_dir)
    analyze_queue_lengths(runs_data, queue_dir)
    
    print("\nAnalysis complete. Results saved to Analysis/results directory.")

if __name__ == "__main__":
    main() 