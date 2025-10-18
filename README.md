# AMD Log Parser

A collection of Python tools for parsing and analyzing HIP/ROCm log files. These tools help visualize GPU workload execution and analyze queue configurations.

## Tools

### 1. parse_log_to_perfetto.py
Parses HIP/ROCm log files and generates Perfetto-compatible JSON traces for GPU workload visualization. This tool extracts dispatch packets, barrier packets, copy operations, and matches them with signal timing information to create a timeline visualization.

**Features:**
- Extracts Dispatch, Barrier, and Copy packets from HIP/ROCm logs
- Matches packets with their completion signals
- Handles signal reuse by matching packets with nearest subsequent signal timing
- Generates Perfetto-compatible JSON for visualization
- Separates events by hardware queue (HWq) and copy engine
- Shows shader names, queue IDs, and memory copy details

**Usage:**
```bash
python parse_log_to_perfetto.py <log_file> [output_file]
```

**Arguments:**
- `log_file` - Path to the HIP/ROCm log file (required)
- `output_file` - Output JSON file path (optional, defaults to `perfetto_trace.json`)

**Example:**
```bash
# Basic usage with default output file
python parse_log_to_perfetto.py test.log

# Specify custom output file
python parse_log_to_perfetto.py test.log my_trace.json
```

**Output:**
The tool generates a JSON file that can be opened in the Perfetto trace viewer:
1. Go to https://ui.perfetto.dev/
2. Open the generated JSON file
3. View the timeline of GPU operations with:
   - Dispatch events (labeled with shader names)
   - Barrier events
   - Memory copy operations
   - Organized by hardware queues and copy engines

### 2. analyze_queues.py
Analyzes HIP/ROCm log files to extract detailed queue information including stream creation patterns, queue priorities, and software-to-hardware queue mappings.

**Features:**
- Detects stream creation API calls (hipStreamCreate, hipStreamCreateWithFlags, hipStreamCreateWithPriority)
- Maps Software Queues (SWq) to Hardware Queues (HWq)
- Identifies queue priorities and flags
- Shows queue usage per process (PID)
- Provides statistics on queue allocation

**Usage:**
```bash
python analyze_queues.py <log_file>
```

**Arguments:**
- `log_file` - Path to the HIP/ROCm log file (required)

**Example:**
```bash
python analyze_queues.py test.log
```

**Output:**
The tool prints a comprehensive report including:
- Total count of unique software and hardware queues
- Stream creation API call statistics
- Hardware queue usage (how many SWqs map to each HWq)
- Software queue to hardware queue mappings
- Stream creation details (flags, priorities)
- Queue information grouped by process ID
- Priority allocation information

## Requirements

- Python 3.x
- No external dependencies (uses only standard library modules)

## Log File Format

These tools expect HIP/ROCm log files generated with appropriate debug logging enabled. The log files should contain:
- Dispatch, Barrier, and Copy packet information
- Signal timing data
- Queue creation and mapping information
- Shader names

## Example Workflow

1. **Generate a HIP/ROCm log file** with debugging enabled
2. **Analyze queue configuration:**
   ```bash
   python analyze_queues.py test.log
   ```
3. **Generate Perfetto trace for visualization:**
   ```bash
   python parse_log_to_perfetto.py test.log trace.json
   ```
4. **View the trace** at https://ui.perfetto.dev/

## Author

Saleel Kudchadker

## License

See LICENSE file for details.