use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Returns true only for globally routable unicast addresses.
///
/// The list deliberately rejects special-purpose ranges, even when a Rust
/// standard-library predicate classifies them as neither private nor local.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

pub fn is_public_socket_addr(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(addr) => addr.port() != 0 && is_public_ipv4(*addr.ip()),
        SocketAddr::V6(addr) => {
            addr.port() != 0 && addr.scope_id() == 0 && is_public_ipv6(*addr.ip())
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
    {
        return false;
    }

    let bits = u32::from(ip);
    // Special-purpose space not covered by the standard-library predicates.
    ![
        (0x0000_0000, 8),  // 0.0.0.0/8
        (0x6440_0000, 10), // 100.64.0.0/10 (shared address space)
        (0xc000_0000, 24), // 192.0.0.0/24 (protocol assignments)
        (0xc000_0200, 24), // 192.0.2.0/24 (documentation)
        (0xc058_6300, 24), // 192.88.99.0/24 (deprecated relay)
        (0xc612_0000, 15), // 198.18.0.0/15 (benchmarking)
        (0xc633_6400, 24), // 198.51.100.0/24 (documentation)
        (0xcb00_7100, 24), // 203.0.113.0/24 (documentation)
        (0xf000_0000, 4),  // 240.0.0.0/4 (reserved)
    ]
    .iter()
    .any(|(network, prefix)| bits & (u32::MAX << (32 - prefix)) == *network)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    // Global-unicast allocation is 2000::/3. Other IPv6 address classes and
    // the following embedded/protocol ranges are not accepted as public peers.
    let global_unicast = bits >> 125 == 1;
    let mapped_ipv4 = bits >> 32 == 0xffff;
    let segments = ip.segments();
    let protocol_assignments_2001 = segments[0] == 0x2001 && segments[1] <= 0x01ff;
    let documentation_2001 = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let documentation_3fff = segments[0] == 0x3fff && segments[1] & 0xf000 == 0;
    let six_to_four = segments[0] == 0x2002;

    global_unicast
        && !mapped_ipv4
        && !protocol_assignments_2001
        && !documentation_2001
        && !documentation_3fff
        && !six_to_four
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_unique_local()
        && !ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::{is_public_ip, is_public_socket_addr};
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn allows_global_unicast_addresses() {
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "rejected {ip}");
        }
    }

    #[test]
    fn rejects_non_global_ipv4_ranges() {
        for ip in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.2",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
    }

    #[test]
    fn rejects_non_global_ipv6_ranges() {
        for ip in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001:20::1",
            "2002::1",
            "3fff::1",
            "64:ff9b::808:808",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
    }

    #[test]
    fn rejects_zero_port_and_scoped_ipv6_socket_addresses() {
        assert!(!is_public_socket_addr("8.8.8.8:0".parse().unwrap()));
        assert!(!is_public_socket_addr(
            "[2606:4700:4700::1111%1]:443".parse().unwrap()
        ));
        assert!(is_public_socket_addr(SocketAddr::new(
            IpAddr::V4("1.1.1.1".parse().unwrap()),
            443,
        )));
    }
}
