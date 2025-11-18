use clap::Parser;
use pnet::packet::icmp::{IcmpTypes, echo_request};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Types, echo_request as echo_request_v6};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, icmp_packet_iter, icmpv6_packet_iter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;
use std::io::{self, Write};

/// MTU testing tool - Test the Maximum Transmission Unit to target host
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target host IP address or domain name
    target: String,

    /// Starting MTU size (bytes)
    #[arg(short, long, default_value_t = 1500)]
    start: usize,

    /// Minimum MTU size (bytes)
    #[arg(short, long, default_value_t = 1280)]
    min: usize,

    /// Step size for each reduction (bytes)
    #[arg(short = 'p', long, default_value_t = 50)]
    step: usize,

    /// Timeout duration (milliseconds)
    #[arg(short = 'w', long, default_value_t = 2000)]
    timeout: u64,

    /// Display MTU calculation for VPN/tunnel protocols (WireGuard, OpenVPN, VXLAN)
    #[arg(short = 'c', long)]
    calculate: bool,
}

fn main() {
    let args = Args::parse();

    // Resolve target IP or domain name
    let target_ip: IpAddr = match resolve_target(&args.target) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Check ICMP sending permission
    if let Err(e) = check_icmp_permission(target_ip) {
        eprintln!("Error: {}", e);
        eprintln!("Hint: Please run this program with sudo to get permission to send ICMP packets");
        std::process::exit(1);
    }

    println!("Starting MTU test");
    println!("Target: {}", target_ip);
    println!("Starting size: {} bytes", args.start);
    println!("Minimum size: {} bytes", args.min);
    println!("Step: {} bytes", args.step);
    println!("Timeout: {} ms", args.timeout);
    println!("{}", "=".repeat(50));

    // Binary search for optimal MTU
    let mtu = find_mtu_binary_search(target_ip, args.min, args.start, args.timeout);

    println!("{}", "=".repeat(50));
    if let Some(mtu_size) = mtu {
        println!("✓ Maximum MTU found: {} bytes", mtu_size);
        
        // If calculate option is enabled, display VPN/tunnel protocol MTU
        if args.calculate {
            println!("\n{}", "=".repeat(50));
            println!("VPN/Tunnel Protocol MTU Calculation (Based on detected MTU: {} bytes)", mtu_size);
            println!("{}", "=".repeat(50));
            calculate_vpn_mtu(mtu_size, target_ip);
        }
    } else {
        println!("✗ Unable to determine MTU, please check network connection or target host");
    }
}

/// Check if we have permission to send ICMP packets
fn check_icmp_permission(target: IpAddr) -> Result<(), String> {
    // Try to create a test transport channel
    let protocol = match target {
        IpAddr::V4(_) => TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        IpAddr::V6(_) => TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    };
    
    match transport_channel(4096, protocol) {
        Ok(_) => {
            println!("✓ Permission check passed");
            Ok(())
        },
        Err(e) => {
            if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                Err("No permission to send ICMP packets".to_string())
            } else {
                Err(format!("Unable to create transport channel: {}", e))
            }
        }
    }
}

/// Resolve target address (IP or domain name)
fn resolve_target(target: &str) -> Result<IpAddr, String> {
    // First try to parse as IPv4 address
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        println!("Using IPv4 address: {}", ip);
        return Ok(IpAddr::V4(ip));
    }

    // Try to parse as IPv6 address
    if let Ok(ip) = target.parse::<Ipv6Addr>() {
        println!("Using IPv6 address: {}", ip);
        return Ok(IpAddr::V6(ip));
    }

    // If not an IP, resolve as domain name
    println!("Resolving domain name: {}", target);
    
    // Use DNS to resolve domain name
    let addresses: Vec<IpAddr> = format!("{}:0", target)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .map(|addr| addr.ip())
        .collect();

    if addresses.is_empty() {
        return Err(format!("Unable to resolve domain name: {}", target));
    }

    // If only one IP, use it directly
    if addresses.len() == 1 {
        let ip = addresses[0];
        println!("Resolved to IP address: {}", ip);
        return Ok(ip);
    }

    // If multiple IPs, let user choose
    println!("\nDomain {} resolved to multiple IP addresses:", target);
    for (i, ip) in addresses.iter().enumerate() {
        let ip_type = match ip {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        };
        println!("  [{}] {} ({})", i + 1, ip, ip_type);
    }

    loop {
        print!("\nPlease select an IP address to use (1-{}): ", addresses.len());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {}", e))?;

        if let Ok(choice) = input.trim().parse::<usize>() {
            if choice > 0 && choice <= addresses.len() {
                let selected_ip = addresses[choice - 1];
                println!("Selected: {}", selected_ip);
                return Ok(selected_ip);
            }
        }

        println!("Invalid selection, please enter a number between 1 and {}", addresses.len());
    }
}

/// Use binary search to find maximum MTU
fn find_mtu_binary_search(target: IpAddr, mut min: usize, max: usize, timeout: u64) -> Option<usize> {
    let mut last_successful = None;

    while min <= max {
        let mid = (min + max) / 2;
        println!("Testing MTU: {} bytes...", mid);

        match test_mtu(target, mid, timeout) {
            Ok(true) => {
                println!("  ✓ Success - Packet size {} bytes can be transmitted", mid);
                last_successful = Some(mid);
                min = mid + 1;
            }
            Ok(false) => {
                println!("  ✗ Failed - Packet size {} bytes is too large, terminating test", mid);
                break;
            }
            Err(e) => {
                eprintln!("  ! Error: {}, terminating test", e);
                break;
            }
        }
    }

    last_successful
}

/// Test MTU of specific size
fn test_mtu(target: IpAddr, size: usize, timeout_ms: u64) -> Result<bool, String> {
    match target {
        IpAddr::V4(ipv4) => test_mtu_v4(ipv4, size, timeout_ms),
        IpAddr::V6(ipv6) => test_mtu_v6(ipv6, size, timeout_ms),
    }
}

/// Test IPv4 MTU
fn test_mtu_v4(target: Ipv4Addr, size: usize, timeout_ms: u64) -> Result<bool, String> {
    // ICMP Echo Request header 8 bytes
    const ICMP_HEADER_SIZE: usize = 8;
    
    // Data portion size
    let data_size = if size > ICMP_HEADER_SIZE {
        size - ICMP_HEADER_SIZE
    } else {
        return Err("MTU size too small".to_string());
    };

    // Create transport channel
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Failed to create transport channel: {}", e)),
    };

    // Create ICMP Echo Request packet
    let mut buffer = vec![0u8; ICMP_HEADER_SIZE + data_size];
    
    {
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer)
            .ok_or("Failed to create ICMP packet")?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
        icmp_packet.set_identifier(std::process::id() as u16);
        icmp_packet.set_sequence_number(1);

        // Fill data
        let payload = vec![0x42u8; data_size];
        icmp_packet.set_payload(&payload);
    }

    // Calculate checksum
    let icmp_packet_immutable = echo_request::EchoRequestPacket::new(&buffer)
        .ok_or("Failed to create immutable ICMP packet")?;
    let checksum = pnet::packet::icmp::checksum(&pnet::packet::icmp::IcmpPacket::new(icmp_packet_immutable.packet()).unwrap());
    
    {
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer)
            .ok_or("Failed to create ICMP packet")?;
        icmp_packet.set_checksum(checksum);
    }

    // Send packet
    let icmp_packet = MutableEchoRequestPacket::new(&mut buffer)
        .ok_or("Failed to create ICMP packet")?;
    match tx.send_to(icmp_packet, IpAddr::V4(target)) {
        Ok(_) => {},
        Err(e) => return Err(format!("Send failed: {}", e)),
    }

    // Set receive timeout
    let timeout = Duration::from_millis(timeout_ms);
    let start = std::time::Instant::now();

    // Wait for response
    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        if start.elapsed() > timeout {
            return Ok(false); // Timeout is considered as failure
        }

        // Try to receive response (non-blocking check with small sleep)
        if let Ok((packet, addr)) = iter.next() {
            if packet.get_icmp_type() == IcmpTypes::EchoReply && addr == IpAddr::V4(target) {
                return Ok(true);
            }
        }
        
        // Small sleep to avoid busy waiting
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Test IPv6 MTU
fn test_mtu_v6(target: Ipv6Addr, size: usize, timeout_ms: u64) -> Result<bool, String> {
    // ICMPv6 Echo Request header 8 bytes
    const ICMPV6_HEADER_SIZE: usize = 8;
    
    // Data portion size
    let data_size = if size > ICMPV6_HEADER_SIZE {
        size - ICMPV6_HEADER_SIZE
    } else {
        return Err("MTU size too small".to_string());
    };

    // Create transport channel
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Failed to create transport channel: {}", e)),
    };

    // Create ICMPv6 Echo Request packet
    let mut buffer = vec![0u8; ICMPV6_HEADER_SIZE + data_size];
    
    {
        let mut icmp_packet = MutableEchoRequestPacketV6::new(&mut buffer)
            .ok_or("Failed to create ICMPv6 packet")?;

        icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp_packet.set_icmpv6_code(echo_request_v6::Icmpv6Codes::NoCode);
        icmp_packet.set_identifier(std::process::id() as u16);
        icmp_packet.set_sequence_number(1);

        // Fill data
        let payload = vec![0x42u8; data_size];
        icmp_packet.set_payload(&payload);
    }

    // Calculate checksum (ICMPv6 requires source and destination addresses for checksum calculation, simplified here)
    let icmp_packet_immutable = echo_request_v6::EchoRequestPacket::new(&buffer)
        .ok_or("Failed to create immutable ICMPv6 packet")?;
    
    // ICMPv6 checksum calculation requires pseudo-header, here we use pnet's checksum function
    let checksum = pnet::packet::icmpv6::checksum(&pnet::packet::icmpv6::Icmpv6Packet::new(icmp_packet_immutable.packet()).unwrap(), &target, &target);
    
    {
        let mut icmp_packet = MutableEchoRequestPacketV6::new(&mut buffer)
            .ok_or("Failed to create ICMPv6 packet")?;
        icmp_packet.set_checksum(checksum);
    }

    // Send packet
    let icmp_packet = MutableEchoRequestPacketV6::new(&mut buffer)
        .ok_or("Failed to create ICMPv6 packet")?;
    match tx.send_to(icmp_packet, IpAddr::V6(target)) {
        Ok(_) => {},
        Err(e) => return Err(format!("Send failed: {}", e)),
    }

    // Set receive timeout
    let timeout = Duration::from_millis(timeout_ms);
    let start = std::time::Instant::now();

    // Wait for response
    let mut iter = icmpv6_packet_iter(&mut rx);
    loop {
        if start.elapsed() > timeout {
            return Ok(false); // Timeout is considered as failure
        }

        // Try to receive response (non-blocking check with small sleep)
        if let Ok((packet, addr)) = iter.next() {
            if packet.get_icmpv6_type() == Icmpv6Types::EchoReply && addr == IpAddr::V6(target) {
                return Ok(true);
            }
        }
        
        // Small sleep to avoid busy waiting
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Calculate MTU for VPN/tunnel protocols
fn calculate_vpn_mtu(base_mtu: usize, ip_addr: IpAddr) {
    let is_ipv6 = matches!(ip_addr, IpAddr::V6(_));
    
    println!("\n【WireGuard MTU Calculation】");
    println!("WireGuard protocol overhead:");
    
    if is_ipv6 {
        // WireGuard over IPv6
        const IPV6_HEADER: usize = 40;      // IPv6 header
        const UDP_HEADER: usize = 8;         // UDP header
        const WIREGUARD_HEADER: usize = 32;  // WireGuard packet header (4-byte type + 4-byte receiver index + 8-byte counter + 16-byte tag)
        
        let total_overhead = IPV6_HEADER + UDP_HEADER + WIREGUARD_HEADER;
        let wireguard_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - IPv6 header: {} bytes", IPV6_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - WireGuard encapsulation: {} bytes", WIREGUARD_HEADER);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ WireGuard interface MTU (IPv6): {} bytes", wireguard_mtu);
    } else {
        // WireGuard over IPv4
        const IPV4_HEADER: usize = 20;       // IPv4 header
        const UDP_HEADER: usize = 8;         // UDP header
        const WIREGUARD_HEADER: usize = 32;  // WireGuard packet header
        
        let total_overhead = IPV4_HEADER + UDP_HEADER + WIREGUARD_HEADER;
        let wireguard_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - IPv4 header: {} bytes", IPV4_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - WireGuard encapsulation: {} bytes", WIREGUARD_HEADER);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ WireGuard interface MTU (IPv4): {} bytes", wireguard_mtu);
    }
    
    println!("\n  Note: WireGuard's IPv4 and IPv6 MTU differ due to IP layer header size differences");
    println!("        IPv4 header is 20 bytes, IPv6 header is 40 bytes, a difference of 20 bytes");
    
    println!("\n【OpenVPN MTU Calculation】");
    println!("OpenVPN protocol overhead (UDP mode):");
    
    if is_ipv6 {
        // OpenVPN over IPv6
        const IPV6_HEADER: usize = 40;          // IPv6 header
        const UDP_HEADER: usize = 8;            // UDP header
        const OPENVPN_HEADER: usize = 1;        // OpenVPN opcode
        const OPENVPN_HMAC: usize = 20;         // HMAC-SHA1 (default)
        const OPENVPN_IV: usize = 16;           // Initialization Vector (AES)
        const OPENVPN_PADDING: usize = 16;      // Encryption padding (maximum)
        
        let total_overhead = IPV6_HEADER + UDP_HEADER + OPENVPN_HEADER + OPENVPN_HMAC + OPENVPN_IV + OPENVPN_PADDING;
        let openvpn_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - IPv6 header: {} bytes", IPV6_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - OpenVPN opcode: {} bytes", OPENVPN_HEADER);
        println!("  - HMAC-SHA1: {} bytes", OPENVPN_HMAC);
        println!("  - IV (Initialization Vector): {} bytes", OPENVPN_IV);
        println!("  - Encryption padding (max): {} bytes", OPENVPN_PADDING);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ OpenVPN Tun interface MTU (IPv6): {} bytes", openvpn_mtu);
    } else {
        // OpenVPN over IPv4
        const IPV4_HEADER: usize = 20;          // IPv4 header
        const UDP_HEADER: usize = 8;            // UDP header
        const OPENVPN_HEADER: usize = 1;        // OpenVPN opcode
        const OPENVPN_HMAC: usize = 20;         // HMAC-SHA1 (default)
        const OPENVPN_IV: usize = 16;           // Initialization Vector (AES)
        const OPENVPN_PADDING: usize = 16;      // Encryption padding (maximum)
        
        let total_overhead = IPV4_HEADER + UDP_HEADER + OPENVPN_HEADER + OPENVPN_HMAC + OPENVPN_IV + OPENVPN_PADDING;
        let openvpn_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - IPv4 header: {} bytes", IPV4_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - OpenVPN opcode: {} bytes", OPENVPN_HEADER);
        println!("  - HMAC-SHA1: {} bytes", OPENVPN_HMAC);
        println!("  - IV (Initialization Vector): {} bytes", OPENVPN_IV);
        println!("  - Encryption padding (max): {} bytes", OPENVPN_PADDING);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ OpenVPN Tun interface MTU (IPv4): {} bytes", openvpn_mtu);
    }
    
    println!("\n  Note: OpenVPN overhead depends on encryption algorithm and authentication method");
    println!("        Different cipher suites will have different overheads");
    
    println!("\n【VXLAN MTU Calculation】");
    println!("VXLAN protocol overhead:");
    
    if is_ipv6 {
        // VXLAN over IPv6
        const IPV6_HEADER: usize = 40;      // Outer IPv6 header
        const UDP_HEADER: usize = 8;        // UDP header
        const VXLAN_HEADER: usize = 8;      // VXLAN header
        const INNER_ETH: usize = 14;        // Inner Ethernet header
        
        let total_overhead = IPV6_HEADER + UDP_HEADER + VXLAN_HEADER + INNER_ETH;
        let vxlan_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - Outer IPv6 header: {} bytes", IPV6_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - VXLAN header: {} bytes", VXLAN_HEADER);
        println!("  - Inner Ethernet header: {} bytes", INNER_ETH);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ VXLAN interface MTU (IPv6): {} bytes", vxlan_mtu);
    } else {
        // VXLAN over IPv4
        const IPV4_HEADER: usize = 20;      // Outer IPv4 header
        const UDP_HEADER: usize = 8;        // UDP header
        const VXLAN_HEADER: usize = 8;      // VXLAN header
        const INNER_ETH: usize = 14;        // Inner Ethernet header
        
        let total_overhead = IPV4_HEADER + UDP_HEADER + VXLAN_HEADER + INNER_ETH;
        let vxlan_mtu = base_mtu.saturating_sub(total_overhead);
        
        println!("  - Outer IPv4 header: {} bytes", IPV4_HEADER);
        println!("  - UDP header: {} bytes", UDP_HEADER);
        println!("  - VXLAN header: {} bytes", VXLAN_HEADER);
        println!("  - Inner Ethernet header: {} bytes", INNER_ETH);
        println!("  - Total overhead: {} bytes", total_overhead);
        println!("  ➜ VXLAN interface MTU (IPv4): {} bytes", vxlan_mtu);
    }
    
    println!("\n  Note: VXLAN is a Layer 2 tunnel protocol that encapsulates complete Ethernet frames");
    
    println!("\n{}", "=".repeat(50));
    println!("MTU Configuration Recommendations:");
    println!("{}", "=".repeat(50));
    println!("  Base network MTU: {} bytes", base_mtu);
    if is_ipv6 {
        println!("  WireGuard (IPv6): Configure MTU = {}", base_mtu.saturating_sub(80));
        println!("  OpenVPN (IPv6):   Configure MTU = {}", base_mtu.saturating_sub(101));
        println!("  VXLAN (IPv6):     Configure MTU = {}", base_mtu.saturating_sub(70));
    } else {
        println!("  WireGuard (IPv4): Configure MTU = {}", base_mtu.saturating_sub(60));
        println!("  OpenVPN (IPv4):   Configure MTU = {}", base_mtu.saturating_sub(81));
        println!("  VXLAN (IPv4):     Configure MTU = {}", base_mtu.saturating_sub(50));
    }
    println!("\n  Tip: For safety, you can subtract an additional 10-20 bytes when configuring");
}
