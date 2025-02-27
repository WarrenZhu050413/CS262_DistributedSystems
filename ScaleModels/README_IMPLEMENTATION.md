# Distributed System Model with Logical Clocks

This project implements a model of a small, asynchronous distributed system with logical clocks. The system simulates multiple virtual machines running at different speeds, communicating with each other, and using logical clocks to track event ordering.

## Project Structure

- `main.py`: Main script to set up and run the distributed system model
- `virtual_machine.py`: Implementation of the VirtualMachine class
- `analyze_logs.py`: Script to analyze logs and generate visualizations
- `EngineeringNotebook.md`: Documentation of design decisions and observations
- `requirements.txt`: List of dependencies

## Setup

1. Create a virtual environment (optional but recommended):
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Running the System

To run the distributed system model with default settings (3 VMs for 60 seconds):

```
python main.py
```

You can customize the runtime and number of VMs:

```
python main.py --runtime 120 --vm-count 3 --base-port 10000
```

Parameters:
- `--runtime`: Duration to run the simulation in seconds (default: 60)
- `--vm-count`: Number of virtual machines to create (default: 3)
- `--base-port`: Base port number for VM communication (default: 10000)

## Analyzing Logs

After running the system, you can analyze the logs using the provided script:

```
python analyze_logs.py
```

This will:
1. Parse all log files in the `logs` directory
2. Print statistics about events, message queues, and logical clock rates
3. Generate visualization plots of logical clock values and queue lengths over time
4. Save the plots to the `logs` directory

## Experiment Design

As per the assignment requirements, you should:

1. Run the model at least 5 times for at least 1 minute each time
2. Examine the logs and note observations in the engineering notebook
3. Try running with:
   - Different variations in clock cycles
   - Different probabilities of internal events

## Implementation Details

Each virtual machine:
- Runs at a random clock rate between 1-6 ticks per second
- Has a network queue and a message queue
- Communicates with other VMs using sockets
- Maintains a logical clock according to Lamport's rules
- Logs all events to a file

On each clock cycle, the VM either:
1. Processes a message from its queue
2. Performs a random action (send message to one VM, send to another VM, send to all VMs, or internal event)

See `EngineeringNotebook.md` for more detailed design decisions and observations. 