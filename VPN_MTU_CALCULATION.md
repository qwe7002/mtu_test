# VPN/Tunnel Protocol MTU Calculation Guide

This tool now supports automatic MTU calculation for WireGuard, OpenVPN, and VXLAN.

## Usage

```bash
# Basic MTU test
sudo ./target/release/mtu_test 8.8.8.8

# MTU test + VPN MTU calculation
sudo ./target/release/mtu_test -c 8.8.8.8

# Test IPv6 target and calculate VPN MTU
sudo ./target/release/mtu_test -c 2001:4860:4860::8888
```

## Protocol Overhead Details

### 1. WireGuard

WireGuard is a modern, high-performance VPN protocol.

#### IPv4 Environment
- **IPv4 Header**: 20 bytes
- **UDP Header**: 8 bytes
- **WireGuard Encapsulation**: 32 bytes
  - Type field: 4 bytes
  - Receiver index: 4 bytes
  - Counter: 8 bytes
  - Authentication tag: 16 bytes
- **Total Overhead**: 60 bytes

**Formula**: `WireGuard MTU = Base MTU - 60`

**Example**: Base MTU 1500 → WireGuard MTU = 1440

#### IPv6 Environment
- **IPv6 Header**: 40 bytes
- **UDP Header**: 8 bytes
- **WireGuard Encapsulation**: 32 bytes
- **Total Overhead**: 80 bytes

**Formula**: `WireGuard MTU = Base MTU - 80`

**Example**: Base MTU 1500 → WireGuard MTU = 1420

**Note**: WireGuard's MTU differs by 20 bytes between IPv4 and IPv6 environments because the IPv6 header is 20 bytes larger than the IPv4 header.

### 2. OpenVPN

OpenVPN is the most popular open-source VPN solution. Overhead depends on encryption and authentication configuration.

#### IPv4 Environment (UDP mode, AES + HMAC-SHA1)
- **IPv4 Header**: 20 bytes
- **UDP Header**: 8 bytes
- **OpenVPN Opcode**: 1 byte
- **HMAC-SHA1**: 20 bytes
- **Initialization Vector (IV)**: 16 bytes
- **Encryption Padding (max)**: 16 bytes
- **Total Overhead**: 81 bytes

**Formula**: `OpenVPN MTU = Base MTU - 81`

**Example**: Base MTU 1500 → OpenVPN MTU = 1419

#### IPv6 Environment
- **IPv6 Header**: 40 bytes
- **UDP Header**: 8 bytes
- **OpenVPN Opcode**: 1 byte
- **HMAC-SHA1**: 20 bytes
- **Initialization Vector (IV)**: 16 bytes
- **Encryption Padding (max)**: 16 bytes
- **Total Overhead**: 101 bytes

**Formula**: `OpenVPN MTU = Base MTU - 101`

**Example**: Base MTU 1500 → OpenVPN MTU = 1399

**Note**: 
- Different encryption algorithms will have different overheads
- AES-256-GCM has approximately 28 bytes overhead (including IV and authentication tag)
- ChaCha20-Poly1305 has similar overhead
- TCP mode has larger overhead (additional 20 bytes TCP header)

### 3. VXLAN

VXLAN (Virtual Extensible LAN) is a Layer 2 network virtualization technology.

#### IPv4 Environment
- **Outer IPv4 Header**: 20 bytes
- **UDP Header**: 8 bytes
- **VXLAN Header**: 8 bytes
- **Inner Ethernet Header**: 14 bytes
- **Total Overhead**: 50 bytes

**Formula**: `VXLAN MTU = Base MTU - 50`

**Example**: Base MTU 1500 → VXLAN MTU = 1450

#### IPv6 Environment
- **Outer IPv6 Header**: 40 bytes
- **UDP Header**: 8 bytes
- **VXLAN Header**: 8 bytes
- **Inner Ethernet Header**: 14 bytes
- **Total Overhead**: 70 bytes

**Formula**: `VXLAN MTU = Base MTU - 70`

**Example**: Base MTU 1500 → VXLAN MTU = 1430

**Note**: VXLAN encapsulates complete Ethernet frames, allowing transmission of any Layer 2 protocol.

## MTU Configuration Recommendations

### Standard Ethernet (MTU 1500)

| Protocol | IPv4 MTU | IPv6 MTU |
|----------|----------|----------|
| WireGuard | 1440 | 1420 |
| OpenVPN | 1419 | 1399 |
| VXLAN | 1450 | 1430 |

### Jumbo Frame (MTU 9000)

| Protocol | IPv4 MTU | IPv6 MTU |
|----------|----------|----------|
| WireGuard | 8940 | 8920 |
| OpenVPN | 8919 | 8899 |
| VXLAN | 8950 | 8930 |

### PPPoE Environment (MTU 1492)

| Protocol | IPv4 MTU | IPv6 MTU |
|----------|----------|----------|
| WireGuard | 1432 | 1412 |
| OpenVPN | 1411 | 1391 |
| VXLAN | 1442 | 1422 |

## Configuration Examples

### WireGuard Configuration

```ini
[Interface]
# IPv4 environment
Address = 10.0.0.1/24
MTU = 1440

# IPv6 environment
Address = fd00::1/64
MTU = 1420
```

### OpenVPN Configuration

```
# Server configuration
tun-mtu 1419

# Client configuration
tun-mtu 1419
```

### VXLAN Configuration

```bash
# IPv4 environment
ip link add vxlan0 type vxlan id 100 dstport 4789 dev eth0
ip link set vxlan0 mtu 1450 up

# IPv6 environment
ip link add vxlan0 type vxlan id 100 dstport 4789 dev eth0
ip link set vxlan0 mtu 1430 up
```

## Security Recommendations

When configuring, it's recommended to subtract an additional 10-20 bytes from the calculated MTU as a safety margin to handle:

1. **Path MTU Changes**: Network paths may change, resulting in lower MTU
2. **Additional Encapsulation**: Some network devices may add extra headers (such as VLAN tags)
3. **Fragmentation Avoidance**: Leaving margin helps better avoid IP fragmentation

**Recommended Configuration**:
- WireGuard IPv4: `Base MTU - 70` (instead of -60)
- WireGuard IPv6: `Base MTU - 90` (instead of -80)
- OpenVPN IPv4: `Base MTU - 100` (instead of -81)
- OpenVPN IPv6: `Base MTU - 120` (instead of -101)
- VXLAN IPv4: `Base MTU - 60` (instead of -50)
- VXLAN IPv6: `Base MTU - 80` (instead of -70)

## Testing and Verification

After configuring VPN, it's recommended to perform actual testing:

```bash
# Test MTU on VPN interface
ping -M do -s 1400 -c 4 target_address

# Gradually increase packet size to find maximum usable value
ping -M do -s 1420 -c 4 target_address
ping -M do -s 1440 -c 4 target_address
```

If you see "Message too long" or "Packet needs to be fragmented" errors, it means the MTU is set too large.

## References

- [WireGuard Official Documentation](https://www.wireguard.com/)
- [OpenVPN MTU Configuration Guide](https://openvpn.net/community-resources/how-to/)
- [VXLAN RFC 7348](https://tools.ietf.org/html/rfc7348)
