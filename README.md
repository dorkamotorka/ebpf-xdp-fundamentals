# Hands-On with XDP: Packet Parsing Example

Tutorial link: https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e

This repository contains the example code used in the “Hands-On with XDP: eBPF for High-Performance Networking” tutorial.  
It demonstrates how an XDP program parses Ethernet, IPv4/IPv6, TCP, UDP, and ICMP headers using safe helpers and the `xdp_md` context.

## What this example shows
- Attaching an XDP program to a network interface  
- Parsing L2/L3/L4 headers with `parse_helpers.h`  
- Extracting IPs, ports, and protocol metadata  
- Logging header information with `bpf_printk()`  
- Returning XDP actions such as `XDP_PASS` or `XDP_DROP`

## Files
- `xdp.c` — The XDP program with protocol parsing  
- `parse_helpers.h` — Minimal helpers for safe header access  
- `main.go` — Loads and attaches the XDP program using `ebpf-go`

## Running the example
1. Compile the eBPF kernel program:
   ```bash
   go generate
   ```
2. Build the Go program:
   ```bash
   go build
   ```
3. Run the program:
   ```bash
   sudo ./xdp -i <interface>
   ```
