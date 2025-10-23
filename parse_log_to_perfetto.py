#!/usr/bin/env python3
"""
Parse HIP/ROCm log files and generate Perfetto-compatible JSON trace
Handles signal reuse by matching packets with nearest subsequent signal timing

Author: Saleel Kudchadker
"""

import re
import json
from collections import defaultdict

def parse_log_file(log_file_path):
    """Parse the log file and extract packet and signal information"""

    packets = []
    signals = []  # List of all signal instances with line number
    current_shader = None

    # Patterns
    # Support both "ShaderName" and "Graph shader name" formats
    shader_pattern = re.compile(r'(?:Graph\s+)?(?:shader name|ShaderName)\s*:\s*([^,\n]+)')
    # Make filename optional - look for :4: or :5: followed by optional filename or spaces, then timestamp
    dispatch_pattern = re.compile(
        r':[45]:(?:[a-z]+\.cpp)?\s*:?\d*\s*:\s*(\d+)\s+us:.*?'
        r'SWq=(0x[0-9a-f]+),\s*HWq=(0x[0-9a-f]+),\s*id=(\d+),\s*'
        r'Dispatch Header.*?'
        r'\(type=\d+,\s*barrier=\d+,\s*acquire=(\d+),\s*release=(\d+)\),\s*'
        r'setup=(\d+),\s*'
        r'grid=\[(\d+),\s*(\d+),\s*(\d+)\],\s*'
        r'workgroup=\[(\d+),\s*(\d+),\s*(\d+)\],\s*'
        r'private_seg_size=(\d+),\s*'
        r'group_seg_size=(\d+),.*?'
        r'completion_signal=(0x[0-9a-f]+).*?'
        r'rptr=(\d+),\s*wptr=(\d+)'
    )
    barrier_pattern = re.compile(
        r':[45]:(?:[a-z]+\.cpp)?\s*:?\d*\s*:\s*(\d+)\s+us:.*?'
        r'SWq=(0x[0-9a-f]+),\s*HWq=(0x[0-9a-f]+),\s*id=(\d+),\s*'
        r'Barrier(?:AND|Value) Header.*?'
        r'\(type=\d+,\s*barrier=\d+,\s*acquire=(\d+),\s*release=(\d+)\).*?'
        r'completion_signal=(0x[0-9a-f]+).*?'
        r'rptr=(\d+),\s*wptr=(\d+)'
    )
    copy_pattern = re.compile(
        r':[45]:(?:[a-z]+\.cpp)?\s*:?\d*\s*:\s*(\d+)\s+us:.*?'
        r'HSA Copy copy_engine=(0x[0-9a-f]+),\s*'
        r'dst=(0x[0-9a-f]+),\s*src=(0x[0-9a-f]+),\s*size=(\d+).*?'
        r'completion_signal=(0x[0-9a-f]+)'
    )
    signal_pattern = re.compile(
        r'Signal = \((0x[0-9a-f]+)\),\s*'
        r'Translated start/end = (\d+)\s*/\s*(\d+),\s*'
        r'Elapsed = (\d+)\s*ns'
    )

    pid_pattern = re.compile(r'\[pid:(\d+)')

    print(f"Parsing log file: {log_file_path}")
    print("This may take a while for large files...")

    line_count = 0
    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_count += 1
            if line_count % 100000 == 0:
                print(f"Processed {line_count} lines... (Found {len(packets)} packets, {len(signals)} signals)")

            # Check for shader name
            shader_match = shader_pattern.search(line)
            if shader_match:
                current_shader = shader_match.group(1).strip()
                continue

            # Extract PID
            pid_match = pid_pattern.search(line)
            pid = pid_match.group(1) if pid_match else "unknown"

            # Check for Dispatch packet
            dispatch_match = dispatch_pattern.search(line)
            if dispatch_match:
                timestamp_us = int(dispatch_match.group(1))
                swq = dispatch_match.group(2)
                hwq = dispatch_match.group(3)
                queue_id = dispatch_match.group(4)
                acquire = dispatch_match.group(5)
                release = dispatch_match.group(6)
                setup = dispatch_match.group(7)
                grid_x = dispatch_match.group(8)
                grid_y = dispatch_match.group(9)
                grid_z = dispatch_match.group(10)
                workgroup_x = dispatch_match.group(11)
                workgroup_y = dispatch_match.group(12)
                workgroup_z = dispatch_match.group(13)
                private_seg_size = dispatch_match.group(14)
                group_seg_size = dispatch_match.group(15)
                completion_signal = dispatch_match.group(16)
                rptr = dispatch_match.group(17)
                wptr = dispatch_match.group(18)

                packets.append({
                    'type': 'Dispatch',
                    'line_num': line_count,
                    'timestamp_us': timestamp_us,
                    'swq': swq,
                    'hwq': hwq,
                    'queue_id': queue_id,
                    'acquire': acquire,
                    'release': release,
                    'setup': setup,
                    'grid': [grid_x, grid_y, grid_z],
                    'workgroup': [workgroup_x, workgroup_y, workgroup_z],
                    'private_seg_size': private_seg_size,
                    'group_seg_size': group_seg_size,
                    'completion_signal': completion_signal,
                    'rptr': rptr,
                    'wptr': wptr,
                    'shader': current_shader,
                    'pid': pid
                })
                continue

            # Check for Barrier packet
            barrier_match = barrier_pattern.search(line)
            if barrier_match:
                timestamp_us = int(barrier_match.group(1))
                swq = barrier_match.group(2)
                hwq = barrier_match.group(3)
                queue_id = barrier_match.group(4)
                acquire = barrier_match.group(5)
                release = barrier_match.group(6)
                completion_signal = barrier_match.group(7)
                rptr = barrier_match.group(8)
                wptr = barrier_match.group(9)

                packets.append({
                    'type': 'Barrier',
                    'line_num': line_count,
                    'timestamp_us': timestamp_us,
                    'swq': swq,
                    'hwq': hwq,
                    'queue_id': queue_id,
                    'acquire': acquire,
                    'release': release,
                    'completion_signal': completion_signal,
                    'rptr': rptr,
                    'wptr': wptr,
                    'shader': None,
                    'pid': pid
                })
                continue

            # Check for Copy packet
            copy_match = copy_pattern.search(line)
            if copy_match:
                timestamp_us = int(copy_match.group(1))
                copy_engine = copy_match.group(2)
                dst = copy_match.group(3)
                src = copy_match.group(4)
                size = copy_match.group(5)
                completion_signal = copy_match.group(6)

                packets.append({
                    'type': 'Copy',
                    'line_num': line_count,
                    'timestamp_us': timestamp_us,
                    'copy_engine': copy_engine,
                    'dst': dst,
                    'src': src,
                    'size': size,
                    'completion_signal': completion_signal,
                    'shader': None,
                    'pid': pid
                })
                continue

            # Check for Signal timing
            signal_match = signal_pattern.search(line)
            if signal_match:
                signal_addr = signal_match.group(1)
                start_ns = int(signal_match.group(2))
                end_ns = int(signal_match.group(3))
                elapsed_ns = int(signal_match.group(4))

                signals.append({
                    'line_num': line_count,
                    'signal_addr': signal_addr,
                    'start_ns': start_ns,
                    'end_ns': end_ns,
                    'elapsed_ns': elapsed_ns,
                    'used': False  # Track if this signal instance has been matched
                })
                continue

    print(f"Parsing complete! Processed {line_count} lines")
    print(f"Found {len(packets)} packets and {len(signals)} signal instances")

    return packets, signals


def match_packets_to_signals(packets, signals):
    """Match each packet to its corresponding signal instance"""

    print("\nMatching packets to signals...")

    # Create index of signals by address for faster lookup
    signals_by_addr = defaultdict(list)
    for sig in signals:
        signals_by_addr[sig['signal_addr']].append(sig)

    # Sort each signal list by line number
    for addr in signals_by_addr:
        signals_by_addr[addr].sort(key=lambda x: x['line_num'])

    matched_packets = []
    matched_count = 0
    unmatched_count = 0

    for packet in packets:
        signal_addr = packet['completion_signal']
        packet_line = packet['line_num']

        # Find the nearest signal after this packet
        matching_signal = None
        if signal_addr in signals_by_addr:
            for sig in signals_by_addr[signal_addr]:
                # Find first unused signal that appears after this packet
                # Allow some lines before for signals that might appear slightly before
                if not sig['used'] and sig['line_num'] >= packet_line - 100:
                    matching_signal = sig
                    sig['used'] = True
                    break

        if matching_signal:
            matched_count += 1
            packet_with_timing = packet.copy()
            packet_with_timing['signal_timing'] = {
                'start_ns': matching_signal['start_ns'],
                'end_ns': matching_signal['end_ns'],
                'elapsed_ns': matching_signal['elapsed_ns']
            }
            matched_packets.append(packet_with_timing)
        else:
            unmatched_count += 1

    print(f"Matched: {matched_count} packets")
    print(f"Unmatched: {unmatched_count} packets")

    return matched_packets


def generate_perfetto_json(packets, output_file):
    """Generate Perfetto-compatible JSON from matched packets"""

    trace_events = []

    # Track assignment for different HWq and copy engines
    track_map = {}
    track_counter = 0

    for packet in packets:
        signal_timing = packet.get('signal_timing')
        if not signal_timing:
            continue

        # Convert nanoseconds to microseconds for Perfetto
        start_us = signal_timing['start_ns'] / 1000.0
        dur_us = signal_timing['elapsed_ns'] / 1000.0

        # Determine track/thread ID based on HWq or copy_engine
        if packet['type'] == 'Copy':
            track_key = f"CopyEngine_{packet['copy_engine']}_pid{packet['pid']}"
        else:
            track_key = f"HWq_{packet['hwq']}_pid{packet['pid']}"

        if track_key not in track_map:
            track_map[track_key] = track_counter
            track_counter += 1

        tid = track_map[track_key]

        # Create event name
        if packet['type'] == 'Dispatch' and packet['shader']:
            event_name = packet['shader']
        elif packet['type'] == 'Barrier':
            event_name = 'Event (Barrier)'
        elif packet['type'] == 'Copy':
            event_name = f"Copy ({packet['size']} bytes)"
        else:
            event_name = packet['type']

        # Create trace event
        event = {
            'name': event_name,
            'cat': packet['type'],
            'ph': 'X',  # Complete event
            'ts': start_us,
            'dur': dur_us,
            'pid': int(packet['pid']),
            'tid': tid,
            'args': {
                'log_timestamp_us': packet['timestamp_us'],
                'completion_signal': packet['completion_signal'],
            }
        }

        # Add type-specific arguments
        if packet['type'] == 'Copy':
            event['args'].update({
                'copy_engine': packet['copy_engine'],
                'dst': packet['dst'],
                'src': packet['src'],
                'size': packet['size']
            })
        elif packet['type'] == 'Dispatch':
            event['args'].update({
                'swq': packet['swq'],
                'hwq': packet['hwq'],
                'queue_id': packet['queue_id'],
                'acquire': packet['acquire'],
                'release': packet['release'],
                'setup': packet['setup'],
                'grid': packet['grid'],
                'workgroup': packet['workgroup'],
                'private_seg_size': packet['private_seg_size'],
                'group_seg_size': packet['group_seg_size'],
                'rptr': packet['rptr'],
                'wptr': packet['wptr']
            })
            if packet['shader']:
                event['args']['shader'] = packet['shader']
        elif packet['type'] == 'Barrier':
            event['args'].update({
                'swq': packet['swq'],
                'hwq': packet['hwq'],
                'queue_id': packet['queue_id'],
                'acquire': packet['acquire'],
                'release': packet['release'],
                'rptr': packet['rptr'],
                'wptr': packet['wptr']
            })

        trace_events.append(event)

    # Add thread name metadata
    for track_key, tid in track_map.items():
        # Extract pid from track_key
        pid_match = re.search(r'pid(\d+)', track_key)
        pid = int(pid_match.group(1)) if pid_match else 0

        trace_events.append({
            'name': 'thread_name',
            'ph': 'M',
            'pid': pid,
            'tid': tid,
            'args': {
                'name': track_key
            }
        })

    print(f"Created {len(trace_events) - len(track_map)} trace events")
    print(f"Created {len(track_map)} tracks")

    # Write JSON
    trace_data = {
        'traceEvents': trace_events,
        'displayTimeUnit': 'ns'
    }

    with open(output_file, 'w') as f:
        json.dump(trace_data, f, indent=2)

    print(f"Perfetto trace written to: {output_file}")


def main():
    import sys
    import os

    if len(sys.argv) < 2:
        print("Usage: python parse_log_to_perfetto.py <log_file> [output_file]")
        sys.exit(1)

    log_file = sys.argv[1]

    # Generate default output filename based on input filename
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        input_basename = os.path.basename(log_file)
        # Remove extension if present
        input_name = os.path.splitext(input_basename)[0]
        output_file = f'perfetto_json_{input_name}.json'

    # Parse the log file
    packets, signals = parse_log_file(log_file)

    # Match packets to signal instances
    matched_packets = match_packets_to_signals(packets, signals)

    # Generate Perfetto JSON
    generate_perfetto_json(matched_packets, output_file)

    print("\nDone! You can now open the JSON file in Perfetto:")
    print("  1. Go to https://ui.perfetto.dev/")
    print(f"  2. Open the file: {output_file}")


if __name__ == '__main__':
    main()
