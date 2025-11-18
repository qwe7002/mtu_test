# MTU Testing Tool

A command-line tool written in Rust for testing the Maximum Transmission Unit (MTU) to remote hosts.

## Features

- Test MTU using ICMP Echo Request/Reply (ping)
- **Support for both IPv4 and IPv6**
- Binary search algorithm for quick MTU determination
- Customizable test range and step size
- **Domain name resolution with automatic IP address conversion**
- **Interactive IP selection when domain resolves to multiple addresses (including IPv4 and IPv6)**
- **Automatic ICMP permission detection with clear error messages**
- **Automatic MTU calculation for VPN/tunnel protocols (WireGuard, OpenVPN, VXLAN)**
- **Distinguish MTU calculations between IPv4 and IPv6 environments (WireGuard and other protocols differ)**
- Cross-platform support (requires administrator/root privileges)

## Build

```bash
cargo build --release
```

## Usage

### Basic Usage

```bash
# macOS/Linux requires root privileges
# Using IPv4 address
sudo ./target/release/mtu_test 8.8.8.8

# Using IPv6 address
sudo ./target/release/mtu_test 2001:4860:4860::8888

# Using domain name
sudo ./target/release/mtu_test google.com

# If domain resolves to multiple IPs (including IPv4 and IPv6), program will prompt for selection
sudo ./target/release/mtu_test example.com
# Example output:
# Resolving domain name: example.com
# 
# Domain example.com resolved to multiple IP addresses:
#   [1] 93.184.216.34 (IPv4)
#   [2] 2606:2800:220:1:248:1893:25c8:1946 (IPv6)
# 
# Please select an IP address to use (1-2): 
```

### Command-Line Arguments

```
Usage: mtu_test [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Target host IP address (IPv4/IPv6) or domain name

Options:
  -s, --start <START>      Starting MTU size (bytes) [default: 1500]
  -m, --min <MIN>          Minimum MTU size (bytes) [default: 1280]
  -p, --step <STEP>        Step size for each reduction (bytes) [default: 50]
  -w, --timeout <TIMEOUT>  Timeout duration (milliseconds) [default: 2000]
  -c, --calculate          Display MTU calculation for VPN/tunnel protocols
  -h, --help               Display help information
  -V, --version            Display version information
```

### Examples

```bash
# Test MTU to Google DNS (using IPv4)
sudo ./target/release/mtu_test 8.8.8.8

# Test MTU to Google DNS (using IPv6)
sudo ./target/release/mtu_test 2001:4860:4860::8888

# Test MTU to Google (using domain name)
sudo ./target/release/mtu_test google.com

# Custom test range
sudo ./target/release/mtu_test 1.1.1.1 --start 1500 --min 1200

# Faster test (larger step size)
sudo ./target/release/mtu_test 192.168.1.1 --step 100

# Running without sudo will show a prompt
./target/release/mtu_test 8.8.8.8
# Output:
# Error: No permission to send ICMP packets
# Hint: Please run this program with sudo to get permission to send ICMP packets
```

## How It Works

1. The program tests packets of different sizes using ICMP Echo Request (ping) packets (supports both IPv4 and IPv6)
2. Uses binary search algorithm to quickly locate the maximum transmittable packet size
3. When packets are too large, they are dropped or fragmented by network devices
4. Eventually finds the maximum packet size that can be successfully transmitted

## Notes

- Requires root/administrator privileges to send raw ICMP/ICMPv6 packets
- Some firewalls may block ICMP packets
- IPv6 minimum MTU is 1280 bytes (RFC 8200)
- Some network devices may limit ICMP packet size

## Dependencies

- `pnet`: For network packet operations
- `clap`: For command-line argument parsing

## License

MIT
