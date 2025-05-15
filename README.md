# Hash Sniffer - C++ Network Packet Analyzer

## Overview

**Hash Sniffer** is a C++ network analysis tool that captures packets from a specified network interface and computes cryptographic hashes on the payloads. The tool leverages `libpcap` for real-time packet capture and `OpenSSL` for computing MD5, SHA1, SHA256, and SHA512 hashes. Captured data is structured and saved in JSON format, making it useful for threat hunting, malware forensics, and intrusion detection analysis.

This project demonstrates:

- Proficiency in C++ for low-level networking
- Practical cybersecurity knowledge
- Building efficient CLI tools with structured logging

## Features

- Live packet capture using `libpcap`
- Extraction of source/destination IPs and ports
- Identification of TCP/UDP protocols
- Payload hashing with MD5, SHA1, SHA256, and SHA512
- Logging results as JSON with timestamps and metadata

## Sample Output

A sample log entry written to `sniffer_log.json`:

```json
{
    "timestamp": 1715740000,
    "source_ip": "192.168.0.101",
    "destination_ip": "142.250.72.206",
    "protocol": "TCP",
    "source_port": 443,
    "destination_port": 59120,
    "payload_hashes": {
        "MD5": "9e107d9d372bb6826bd81d3542a419d6",
        "SHA1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "SHA256": "ef797c8118f02d4c602d6cbd9a9d9ba0c6e92b8b1f16b75ad48fb3e4d1c8d2b6",
        "SHA512": "..."
    }
}


