#!/bin/bash

# eBPF XDP Filter Build Script
# This script compiles the eBPF C program to BPF bytecode

set -e

echo "Building eBPF XDP filter..."

# Check if clang is installed
if ! command -v clang &> /dev/null; then
    echo "Error: clang is required to build eBPF programs"
    echo "Install with: sudo apt-get install clang llvm"
    exit 1
fi

# Check if bpf headers are available
if [ ! -d "/usr/include/linux" ]; then
    echo "Error: Linux headers not found"
    echo "Install with: sudo apt-get install linux-headers-$(uname -r)"
    exit 1
fi

# Create output directory
mkdir -p backend/ebpf/build

# Compile eBPF program
clang -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c backend/ebpf/xdp_filter.c \
    -o backend/ebpf/build/xdp_filter.o

echo "✓ eBPF program compiled successfully"
echo "Output: backend/ebpf/build/xdp_filter.o"

# Verify the object file
if command -v llvm-objdump &> /dev/null; then
    echo ""
    echo "Program sections:"
    llvm-objdump -h backend/ebpf/build/xdp_filter.o
fi

echo ""
echo "To load this program, run the application with root privileges on Linux"
echo "The program will automatically attach to the default network interface"
