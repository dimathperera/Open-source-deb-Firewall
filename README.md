# open source debian CLI firewall
 Network Programming Course Project
A lightweight, CLI-based firewall for Linux using nftables, designed as part of an HND Network Programming and Designing coursework. This tool focuses on basic traffic filtering and monitoring with a minimal footprint.

# Course Information
Course: HND Network Programming and Designing
Project: Basic Firewall with Traffic Filtering and Monitoring
Type: Coursework Project
Design Philosophy: Lightweight, CLI-based, educational focus

# Project Overview
This firewall implements a default-allow policy (traffic is allowed unless explicitly blocked), making it safe for testing environments. It provides essential firewall functionality without the complexity of enterprise solutions.

# Key Features
 Basic packet filtering (TCP, UDP, ICMP)
 Real-time traffic monitoring
 Persistent rule storage (JSON)
 Automatic rule restoration
 Simple CLI interface
 Minimal dependencies

# System Requirements
OS: Linux (Kali Linux recommended)
Kernel: nftables support required
Python: 3.6 or higher
RAM: < 50MB (lightweight design)
Disk: < 10MB
