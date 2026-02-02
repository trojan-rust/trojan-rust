//! IP CIDR matcher.

use std::net::IpAddr;

use ipnet::{Ipv4Net, Ipv6Net};

/// Matcher for IP-CIDR and IP-CIDR6 rules.
///
/// CIDRs are stored in sorted, deduplicated vectors.  Lookup is O(n) via
/// linear scan since CIDR containment checks cannot use simple binary search.
#[derive(Debug)]
pub struct CidrMatcher {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

impl CidrMatcher {
    /// Create a new CIDR matcher from unsorted lists.
    pub fn new(mut v4: Vec<Ipv4Net>, mut v6: Vec<Ipv6Net>) -> Self {
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();
        Self { v4, v6 }
    }

    /// Create an empty CIDR matcher.
    pub fn empty() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    /// Check if an IP address is contained in any CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }

    fn contains_v4(&self, addr: std::net::Ipv4Addr) -> bool {
        self.v4.iter().any(|cidr| cidr.contains(&addr))
    }

    fn contains_v6(&self, addr: std::net::Ipv6Addr) -> bool {
        self.v6.iter().any(|cidr| cidr.contains(&addr))
    }

    /// Returns true if no CIDRs are registered.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Total number of CIDR entries.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

impl Default for CidrMatcher {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cidr_v4_contains() {
        let m = CidrMatcher::new(
            vec![
                "192.168.0.0/16".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
            vec![],
        );
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!m.contains(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!m.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn cidr_v4_exact() {
        let m = CidrMatcher::new(vec!["1.2.3.4/32".parse().unwrap()], vec![]);
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!m.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5))));
    }

    #[test]
    fn cidr_v6_contains() {
        let m = CidrMatcher::new(
            vec![],
            vec!["2001:db8::/32".parse().unwrap()],
        );
        assert!(m.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!m.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb9, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn cidr_empty() {
        let m = CidrMatcher::empty();
        assert!(!m.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(m.is_empty());
    }

    #[test]
    fn cidr_mixed() {
        let m = CidrMatcher::new(
            vec!["127.0.0.0/8".parse().unwrap()],
            vec!["::1/128".parse().unwrap()],
        );
        assert!(m.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(m.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!m.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn cidr_overlapping() {
        let m = CidrMatcher::new(
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "10.0.0.0/24".parse().unwrap(),
            ],
            vec![],
        );
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(m.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))));
    }
}
