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
Analyzes HIP/ROCm log files to extract detailed queue information including stream creation patterns, queue priorities, and stream-to-hardware queue mappings.

**Features:**
- Detects all stream creation API calls (hipStreamCreate, hipStreamCreateWithFlags, hipStreamCreateWithPriority)
- Detects stream destroy calls (hipStreamDestroy)
- Maps HIP Streams to Hardware Queues (HWq)
- Identifies queue priorities and flags
- Shows which streams share the same hardware queue (potential contention points)
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
- Total count of unique streams and hardware queues
- Stream → HWq mapping statistics
- Stream creation and destroy API call statistics
- Stream creation details with line numbers (flags, priorities)
- Stream destroy details with line numbers
- Queue information grouped by process ID (PID)
- Priority allocation information
- Hardware Queue Usage Summary showing which streams share each HWq (identifies potential contention)

## Requirements

- Python 3.x
- No external dependencies (uses only standard library modules)

## Log File Format

These tools expect HIP/ROCm log files generated with **AMD_LOG_LEVEL=5** (or higher). This log level is required to capture:
- Dispatch, Barrier, and Copy packet information
- Signal timing data
- Queue creation and mapping information
- Shader names

### Generating Log Files

To generate a log file with the required level of detail:

```bash
# Option 1: Output to stdout (redirect to file)
AMD_LOG_LEVEL=5 ./your_application > logfile.log 2>&1

# Option 2: Use AMD_LOG_LEVEL_FILE to automatically create log files
# This creates files named <filename>_pid<process_id>
AMD_LOG_LEVEL=5 AMD_LOG_LEVEL_FILE=myapp ./your_application
# Output: myapp_pid12345
```

**Note:** `AMD_LOG_LEVEL_FILE=filename` will generate log files with the pattern `filename_pid<pid>` for each process.

## Example Workflow

1. **Generate a HIP/ROCm log file** with AMD_LOG_LEVEL=5:
   ```bash
   AMD_LOG_LEVEL=5 AMD_LOG_LEVEL_FILE=myapp ./your_application
   # This creates myapp_pid<process_id>
   ```
   
2. **Analyze queue configuration:**
   ```bash
   python analyze_queues.py myapp_pid12345
   ```
   
3. **Generate Perfetto trace for visualization:**
   ```bash
   python parse_log_to_perfetto.py myapp_pid12345 trace.json
   ```
   
4. **View the trace** at https://ui.perfetto.dev/

## Author

Saleel Kudchadker

## License

See LICENSE file for details.