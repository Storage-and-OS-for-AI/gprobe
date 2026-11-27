# gprobe LPM Trie Demo

This demo showcases gprobe's LPM (Longest Prefix Matching) Trie functionality for file access control.

## Overview

The demo implements a file access monitoring system using:
- **BPF_MAP_TYPE_LPM_TRIE**: Real LPM Trie map for prefix matching
- **Client/Server Architecture**: gprobe syscall-server and agent
- **Real-time Monitoring**: uprobe-based file access interception

## Files

- `file_access_filter.bpf.c`: BPF program with LPM Trie logic
- `file_access_monitor.c`: Monitor program (gprobe server)
- `file_access_target.c`: Test target program (gprobe client)
- `run_lmp_trie_demo.sh`: Demo execution script
- `Makefile`: Build configuration

## Quick Start

```bash
# Run full demo
./run_lpm_trie_demo.sh

# Build only
./run_lpm_trie_demo.sh --build

# Test only
./run_lpm_trie_demo.sh --test

# Clean
./run_lpm_trie_demo.sh --clean
```

## How It Works

1. **Monitor** (Server): Loads BPF program and initializes LPM Trie with allowed prefixes
2. **Target** (Client): Performs file operations that trigger uprobe events
3. **LPM Trie**: Automatically finds longest matching prefix for access control
4. **Event Queue**: Processes file access events in real-time

## Allowed Prefixes

- `/tmp/`
- `/var/tmp/`
- `/usr/share/`
- `/home/user/documents/`

## Architecture

```
Monitor (Server) → gprobe Server → BPF Maps (LPM Trie, Queue, Counter)
Target (Client)  → gprobe Agent  → Shared Memory
BPF Program      → LPM Trie       → Access Control
```

## Requirements

- Built gprobe runtime
- Linux with BPF support
- Make and GCC 