# Python Port Scanner 🔍

A lightweight, multi-threaded port scanning tool built in Python for educational and network diagnostic purposes. Supports both **TCP Connect** and **SYN (half-open)** scanning techniques and includes banner grabbing for open ports. Developed for the CSE 3320 Operating Systems course at UT Arlington.

## 🚀 Features

- 🔁 Scans multiple IP addresses and ports concurrently
- 🔌 Supports two scan modes: 
  - `connect` (full TCP connection)
  - `syn` (half-open scan using Scapy)
- 🧵 Threaded for fast parallel port scanning
- 📥 Optional banner grabbing from open services
- 🔧 Command-line interface with customizable parameters
- 📄 Results can be printed or saved as a JSON-formatted file

## 🛠 Usage

```bash
# Basic TCP connect scan on ports 1-1024 with banner grabbing
sudo python3 port_scanner.py -t cse3320.org -p 1-1024 -s connect -v --banner -o scan_results.txt
