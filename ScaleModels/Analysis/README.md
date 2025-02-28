# Log Analysis System for Distributed System Model

This directory contains tools for analyzing logs from the distributed system model with logical clocks.

## Overview

The log analysis system consists of:

1. `analyze_logs.py`: Parses log files and creates structured CSV data
2. `analyze_specific_metrics.py`: Performs detailed analysis of key metrics
3. Scripts for visualizing various aspects of the system behavior

## Running the Analysis

### Method 1: Using the Experiment Runner

The easiest way to run experiments and analyze results is to use the `run_experiment.py` script in the main directory:

```bash
# Run 5 default experiments and analyze the results
python run_experiment.py

# Run with different internal event probability (higher number means fewer internal events)
python run_experiment.py --internal-prob 2  # Only 20% of events will be internal

# Run with a smaller clock rate range
python run_experiment.py --min-rate 3 --max-rate 4

# Only analyze existing logs without running new experiments
python run_experiment.py --analyze-only
```

### Method 2: Manual Analysis

You can also run the analysis tools manually:

1. First, parse log files to create structured data:

```bash
python Analysis/analyze_logs.py ./logs/0
```

2. Then, run the specific metrics analysis:

```bash
python Analysis/analyze_specific_metrics.py ./logs
```

## Analysis Outputs

The analysis generates a variety of visualizations:

### Logical Clock Jumps

- Histograms of jump sizes
- Time series of jump sums
- Regression of jump sums vs clock rate

### Logical Clock Drift

- Line graphs of logical clock values over time
- Sums of absolute differences between logical clocks
- Regression of clock rate variance vs logical clock variance

### Message Queue Analysis

- Queue lengths over time
- Consecutive logical clock differences

## Directory Structure

After running the analysis, you'll find the following directory structure:

```
Analysis/
  ├── results/            # Main results directory
  │   ├── jumps/          # Logical clock jumps analysis
  │   ├── drift/          # Logical clock drift analysis
  │   └── queue/          # Queue length analysis
  └── plots/              # Additional plots by run
      ├── 0/              # Results for run 0
      ├── 1/              # Results for run 1
      └── ...
```

## Interpreting Results

### Logical Clock Jumps

Large jumps in logical clock values indicate that a VM received a message with a much higher logical clock value than its own. This can happen when:

- The receiving VM has a slower clock rate
- The sending VM has been very active (lots of events)
- Message delays cause queue buildup

### Logical Clock Drift

Drift between logical clocks shows how the different clock rates affect the advancement of logical time. VMs with higher clock rates will typically have higher logical clock values, but message exchanges help synchronize them.

### Queue Lengths

Queue length patterns reveal how the system handles message processing under different conditions:

- Longer queues indicate a VM can't process messages as fast as they arrive
- Faster VMs (higher clock rates) generally have shorter queues
- Slower VMs tend to accumulate messages 