# AGENTS.md

This file provides guidance for AI agents working on this codebase.

## Project Overview

This repository contains tools for exporting and processing VPP (Vector Packet Processing) telemetry data:

- **vpp-sflow-exporter**: sFlow exporter for VPP
- **vpp-nat44-ipfix-collector**: IPFIX collector for VPP NAT44 session data

## Useful Commands

### Testing `vpp-nat44-ipfix-collector`

Run against a pcap file with verbose logging and metrics dump:

```bash
go run ./cmd/vpp-nat44-ipfix-collector -verbose serve -pcapFile testdata/ipfix20241214.pcap --dumpMetrics=vpp*
```

To focus on logs of interest, pipe through `jq`:

```bash
go run ./cmd/vpp-nat44-ipfix-collector -verbose serve -pcapFile testdata/ipfix20241214.pcap --dumpMetrics=vpp* 2>&1 | jq
```

You can also filter to specific fields:

```bash
go run ./cmd/vpp-nat44-ipfix-collector -verbose serve -pcapFile testdata/ipfix20241214.pcap --dumpMetrics=vpp* 2>&1 | jq '.msg'
```

## Project Structure

- `cmd/` - Main application entry points
  - `vpp-nat44-ipfix-collector/` - IPFIX collector application
  - `vpp-sflow-exporter/` - sFlow exporter application
- `cliutils/` - Common CLI utilities (logging, signal handling, etc.)
- `vppipfix/` - IPFIX processing logic
- `vppsflow/` - sFlow processing logic
- `kafkapusher/` - Kafka integration for pushing data
- `testdata/` - Test pcap files and sample data
