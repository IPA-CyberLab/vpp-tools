# VPP Companions

A collection of tools to enhance observability for [VPP](https://wiki.fd.io/view/VPP) (Vector Packet Processing) deployments.

---

## vpp-sflow-exporter

Receives sFlow packets from [host-sflowd](https://github.com/sflow/host-sflow) (with [vpp-sflow](https://github.com/sflow/vpp-sflow) integration) and exposes network statistics and packet drop information as Prometheus metrics.

WARNING: this is under active development and the features listed below is not yet fully complete.

### Features

- Prometheus metrics
    - Exports the sFlow counter samples and summarized sFlow drop samples as Prometheus metrics
- Pcap export
    - Saves dropped packets as pcap files for offline analysis
- Re-export
    - Forwards received sFlow packets to another collector (e.g., sfacctd for session accounting)

---

## vpp-nat44-ipfix-collector

Ingests IPFIX records from VPP's NAT44 feature and exports session records to Kafka as JSON messages.

WARNING: This tool assumes a patched VPP build, which is currently being upstreamed.

### How It Works

1. VPP exports IPFIX packets for NAT44 session creation and deletion events
2. The collector tracks active sessions in memory
3. When a session is deleted, the collector exports a complete session record to Kafka

This approach transforms event-based IPFIX data into session-based records for easier downstream processing.
