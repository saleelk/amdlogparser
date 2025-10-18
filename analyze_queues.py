#!/usr/bin/env python3
"""
Analyze HIP/ROCm log file to extract queue information:
- Queue creation (hipStreamCreate, hipStreamCreateWithFlags)
- Queue priorities
- SWq to HWq mappings

Author: Saleel Kudchadker
"""

import re
from collections import defaultdict

def analyze_log_file(log_file_path):
    """Analyze the log file for queue information"""

    # Data structures
    stream_creates = []
    swq_hwq_mappings = {}
    queue_priorities = {}
    all_swqs = set()
    all_hwqs = set()
    queue_info = {}

    # Patterns
    stream_create_basic_pattern = re.compile(
        r'hipStreamCreate\s*\(\s*([^)]+)\s*\)'
    )

    stream_create_flags_pattern = re.compile(
        r'hipStreamCreateWithFlags\s*\(\s*([^,]+),\s*(\d+)\s*\)'
    )

    stream_create_priority_pattern = re.compile(
        r'hipStreamCreateWithPriority\s*\(\s*([^,]+),\s*([^,]+),\s*(-?\d+)\s*\)'
    )

    stream_return_basic_pattern = re.compile(
        r'hipStreamCreate:\s*Returned\s+\w+\s*:\s*stream:(0x[0-9a-f]+)'
    )

    stream_return_flags_pattern = re.compile(
        r'hipStreamCreateWithFlags:\s*Returned\s+\w+\s*:\s*stream:(0x[0-9a-f]+)'
    )

    stream_return_priority_pattern = re.compile(
        r'hipStreamCreateWithPriority:\s*Returned\s+\w+\s*:\s*stream:(0x[0-9a-f]+)'
    )

    # Queue priority allocation pattern
    priority_allocation_pattern = re.compile(
        r'Number of allocated hardware queues with low priority:\s*(\d+),\s*'
        r'with normal priority:\s*(\d+),\s*'
        r'with high priority:\s*(\d+)'
    )

    # Selected queue pattern
    selected_queue_pattern = re.compile(
        r'Selected queue.*?:(0x[0-9a-f]+)\s*\((\d+)\)'
    )

    # SWq and HWq pattern
    swq_hwq_pattern = re.compile(
        r'SWq=(0x[0-9a-f]+),\s*HWq=(0x[0-9a-f]+)'
    )

    # PID pattern
    pid_pattern = re.compile(r'\[pid:(\d+)')

    print(f"Analyzing log file: {log_file_path}")
    print("This may take a while for large files...\n")

    line_count = 0
    current_pid = None
    last_stream_create_info = None
    last_priority_info = None

    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_count += 1
            if line_count % 500000 == 0:
                print(f"Processed {line_count} lines...")

            # Extract PID
            pid_match = pid_pattern.search(line)
            if pid_match:
                current_pid = pid_match.group(1)

            # Check for priority allocation info
            priority_match = priority_allocation_pattern.search(line)
            if priority_match:
                last_priority_info = {
                    'low': int(priority_match.group(1)),
                    'normal': int(priority_match.group(2)),
                    'high': int(priority_match.group(3))
                }

            # Check for basic stream creation (hipStreamCreate)
            stream_basic_match = stream_create_basic_pattern.search(line)
            if stream_basic_match and 'hipStreamCreateWith' not in line:  # Avoid matching the other variants
                last_stream_create_info = {
                    'type': 'basic',
                    'flags': None,
                    'priority': None
                }
                stream_creates.append({
                    'line_num': line_count,
                    'pid': current_pid,
                    'type': 'hipStreamCreate',
                    'flags': None,
                    'priority': None,
                    'line': line.strip()
                })

            # Check for stream creation with flags
            stream_flags_match = stream_create_flags_pattern.search(line)
            if stream_flags_match:
                flags = int(stream_flags_match.group(2))
                # Map flags value to name
                if flags == 0x00:
                    flags_name = "hipStreamDefault"
                elif flags == 0x01:
                    flags_name = "hipStreamNonBlocking"
                else:
                    flags_name = f"unknown(0x{flags:x})"

                last_stream_create_info = {
                    'type': 'flags',
                    'flags': flags,
                    'flags_name': flags_name,
                    'priority': None
                }
                stream_creates.append({
                    'line_num': line_count,
                    'pid': current_pid,
                    'type': 'hipStreamCreateWithFlags',
                    'flags': flags,
                    'flags_name': flags_name,
                    'priority': None,
                    'line': line.strip()
                })

            # Check for stream creation with priority
            stream_priority_match = stream_create_priority_pattern.search(line)
            if stream_priority_match:
                priority_val = int(stream_priority_match.group(3))
                # Map priority value to name
                if priority_val == 0:
                    priority_name = "normal"
                elif priority_val == -1:
                    priority_name = "high"
                elif priority_val == 1:
                    priority_name = "low"
                else:
                    priority_name = f"unknown({priority_val})"

                last_stream_create_info = {
                    'type': 'priority',
                    'priority': priority_val,
                    'priority_name': priority_name
                }
                stream_creates.append({
                    'line_num': line_count,
                    'pid': current_pid,
                    'type': 'hipStreamCreateWithPriority',
                    'flags': None,
                    'priority': priority_val,
                    'priority_name': priority_name,
                    'line': line.strip()
                })

            # Check for stream return (basic version)
            stream_return_basic_match = stream_return_basic_pattern.search(line)
            if stream_return_basic_match:
                stream_addr = stream_return_basic_match.group(1)
                if last_stream_create_info is not None:
                    queue_info[stream_addr] = {
                        'type': last_stream_create_info.get('type'),
                        'pid': current_pid,
                        'priority_info': last_priority_info
                    }
                    last_stream_create_info = None

            # Check for stream return (flags version)
            stream_return_flags_match = stream_return_flags_pattern.search(line)
            if stream_return_flags_match:
                stream_addr = stream_return_flags_match.group(1)
                if last_stream_create_info is not None:
                    queue_info[stream_addr] = {
                        'type': last_stream_create_info.get('type'),
                        'flags': last_stream_create_info.get('flags'),
                        'priority': last_stream_create_info.get('priority'),
                        'pid': current_pid,
                        'priority_info': last_priority_info
                    }
                    last_stream_create_info = None

            # Check for stream return (priority version)
            stream_return_priority_match = stream_return_priority_pattern.search(line)
            if stream_return_priority_match:
                stream_addr = stream_return_priority_match.group(1)
                if last_stream_create_info is not None:
                    queue_info[stream_addr] = {
                        'type': last_stream_create_info.get('type'),
                        'priority': last_stream_create_info.get('priority'),
                        'priority_name': last_stream_create_info.get('priority_name'),
                        'pid': current_pid,
                        'priority_info': last_priority_info
                    }
                    last_stream_create_info = None

            # Check for selected queue
            selected_match = selected_queue_pattern.search(line)
            if selected_match:
                hwq = selected_match.group(1)
                ref_count = int(selected_match.group(2))
                all_hwqs.add(hwq)

            # Extract SWq-HWq mappings
            swq_hwq_match = swq_hwq_pattern.search(line)
            if swq_hwq_match:
                swq = swq_hwq_match.group(1)
                hwq = swq_hwq_match.group(2)
                all_swqs.add(swq)
                all_hwqs.add(hwq)

                # Store mapping with PID
                key = (swq, current_pid)
                if key not in swq_hwq_mappings:
                    swq_hwq_mappings[key] = hwq

    print(f"Processed {line_count} lines total\n")

    # Print summary
    print("=" * 80)
    print("QUEUE ANALYSIS SUMMARY")
    print("=" * 80)

    # Count by type
    basic_count = len([s for s in stream_creates if s['type'] == 'hipStreamCreate'])
    flags_count = len([s for s in stream_creates if s['type'] == 'hipStreamCreateWithFlags'])
    priority_count = len([s for s in stream_creates if s['type'] == 'hipStreamCreateWithPriority'])

    print(f"\nTotal Statistics:")
    print(f"   - Unique Software Queues (SWq): {len(all_swqs)}")
    print(f"   - Unique Hardware Queues (HWq): {len(all_hwqs)}")
    print(f"   - Stream creation API calls found: {len(stream_creates)}")
    print(f"     * hipStreamCreate: {basic_count}")
    print(f"     * hipStreamCreateWithFlags: {flags_count}")
    print(f"     * hipStreamCreateWithPriority: {priority_count}")

    print(f"\nHardware Queues (HWq):")
    for i, hwq in enumerate(sorted(all_hwqs), 1):
        # Count how many SWqs map to this HWq
        swq_count = sum(1 for (swq, pid), mapped_hwq in swq_hwq_mappings.items() if mapped_hwq == hwq)
        print(f"   {i}. {hwq} (used by {swq_count} SWq(s))")

    print(f"\nSoftware Queues (SWq):")
    for i, swq in enumerate(sorted(all_swqs), 1):
        # Find corresponding HWq
        hwq_for_swq = None
        for (s, pid), hwq in swq_hwq_mappings.items():
            if s == swq:
                hwq_for_swq = hwq
                break
        print(f"   {i}. {swq} -> maps to HWq {hwq_for_swq}")

    print(f"\nSWq -> HWq Mappings:")
    print(f"   {'SWq':<20} {'PID':<10} {'-> HWq':<20}")
    print(f"   {'-'*20} {'-'*10} {'-'*20}")

    for (swq, pid), hwq in sorted(swq_hwq_mappings.items()):
        print(f"   {swq:<20} {pid:<10} -> {hwq:<20}")

    if stream_creates:
        print(f"\nStream Creation Details:")

        # Group by type
        basic_streams = [s for s in stream_creates if s['type'] == 'hipStreamCreate']
        flags_streams = [s for s in stream_creates if s['type'] == 'hipStreamCreateWithFlags']
        priority_streams = [s for s in stream_creates if s['type'] == 'hipStreamCreateWithPriority']

        if basic_streams:
            print(f"\n   hipStreamCreate ({len(basic_streams)} calls):")
            print(f"     (No flags or priority parameters)")

        if flags_streams:
            print(f"\n   hipStreamCreateWithFlags ({len(flags_streams)} calls):")
            # Group by flags value
            flags_dist = defaultdict(int)
            for sc in flags_streams:
                flags_dist[(sc['flags'], sc['flags_name'])] += 1
            print(f"     Flags distribution:")
            for (flags, flags_name), count in sorted(flags_dist.items()):
                print(f"       Flags 0x{flags:02x} ({flags_name}): {count} streams")

        if priority_streams:
            print(f"\n   hipStreamCreateWithPriority ({len(priority_streams)} calls):")
            # Group by priority
            priority_dist = defaultdict(int)
            for sc in priority_streams:
                priority_dist[(sc['priority'], sc['priority_name'])] += 1
            print(f"     Priority distribution:")
            for (prio_val, prio_name), count in sorted(priority_dist.items()):
                print(f"       Priority {prio_val} ({prio_name}): {count} streams")

        print(f"\n   First 10 stream creation calls:")
        for i, stream_info in enumerate(stream_creates[:10], 1):
            if stream_info['type'] == 'hipStreamCreate':
                print(f"      {i}. Line {stream_info['line_num']}: PID {stream_info['pid']}, Type: Basic (no flags)")
            elif stream_info['type'] == 'hipStreamCreateWithFlags':
                print(f"      {i}. Line {stream_info['line_num']}: PID {stream_info['pid']}, Type: Flags, Flags: 0x{stream_info['flags']:02x} ({stream_info['flags_name']})")
            else:
                print(f"      {i}. Line {stream_info['line_num']}: PID {stream_info['pid']}, Type: Priority, Priority: {stream_info['priority']} ({stream_info['priority_name']})")

        if len(stream_creates) > 10:
            print(f"      ... and {len(stream_creates) - 10} more")

    # Group by PID
    print(f"\nQueue Information by Process (PID):")
    pids = set(pid for (swq, pid) in swq_hwq_mappings.keys())
    for pid in sorted(pids):
        pid_mappings = [(swq, hwq) for (swq, p), hwq in swq_hwq_mappings.items() if p == pid]
        pid_swqs = set(swq for swq, hwq in pid_mappings)
        pid_hwqs = set(hwq for swq, hwq in pid_mappings)

        print(f"\n   PID {pid}:")
        print(f"     - Software Queues: {len(pid_swqs)}")
        print(f"     - Hardware Queues: {len(pid_hwqs)}")
        print(f"     - Mappings:")

        for swq, hwq in sorted(pid_mappings):
            print(f"       - SWq {swq} -> HWq {hwq}")

    # Check for priority information from the log
    if last_priority_info:
        print(f"\nQueue Priority Allocation (last observed):")
        print(f"   - Low priority queues: {last_priority_info['low']}")
        print(f"   - Normal priority queues: {last_priority_info['normal']}")
        print(f"   - High priority queues: {last_priority_info['high']}")
    else:
        print(f"\nNo priority allocation information found in log")

    print("\n" + "=" * 80)

    # Return data for programmatic use
    return {
        'all_swqs': all_swqs,
        'all_hwqs': all_hwqs,
        'mappings': swq_hwq_mappings,
        'stream_creates': stream_creates,
        'queue_info': queue_info
    }


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analyze_queues.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    analyze_log_file(log_file)


if __name__ == '__main__':
    main()

