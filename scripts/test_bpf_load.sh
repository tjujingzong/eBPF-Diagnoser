#!/bin/bash
# Test script to verify BPF CO-RE fix for sched_wakeup
# Run as root: sudo bash test_bpf_load.sh

set -e

cd "$(dirname "$0")"

echo "=== Testing cpu_probe.bpf.o load with CO-RE fix ==="

# Test load using bpftool if available, otherwise use a simple C test
if command -v bpftool &>/dev/null; then
    echo "Using bpftool to load and test..."
    bpftool prog load bpf/cpu_probe.bpf.o /sys/fs/bpf/test_cpu_probe
    echo "SUCCESS: BPF object loaded!"
    bpftool prog show pinned /sys/fs/bpf/test_cpu_probe
    rm -f /sys/fs/bpf/test_cpu_probe
else
    echo "bpftool not available, using loader..."
    echo '{"id":1,"cmd":"LOAD","probe":"cpu","obj_path":"bpf/cpu_probe.bpf.o"}' | timeout 5 bpf/loader/bpf_loader
fi

echo ""
echo "=== Test complete ==="
