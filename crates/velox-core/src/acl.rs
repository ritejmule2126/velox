//! CIDR allow / deny lists for client addresses.
//!
//! A client is admitted iff it matches **no** `deny` entry and — when an `allow`
//! list exists — **at least one** `allow` entry (deny always wins). An empty
//! filter admits everyone. Global and per-route filters are *both* applied, so
//! a route can only narrow what the global policy lets through.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:203.0.113.9`, which a dual-stack
//! listener reports for IPv4 clients) are matched as the IPv4 address they
//! carry; otherwise an IPv4 deny rule could be sidestepped by the socket family.

use ipnet::IpNet;
use std::net::IpAddr;

/// Why a client was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// Matched a `deny` entry.
    Denied,
    /// An `allow` list exists and the client is not on it.
    NotAllowed,
}

impl Denial {
    /// A low-cardinality metric label.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Denied => "deny",
            Self::NotAllowed => "not_allowed",
        }
    }
}

/// A compiled allow/deny pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpFilter {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

/// The address to match: IPv4-mapped IPv6 becomes the IPv4 it carries.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn contains(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

impl IpFilter {
    /// Build a filter from configured lists.
    pub fn new(allow: &[IpNet], deny: &[IpNet]) -> Self {
        Self { allow: allow.to_vec(), deny: deny.to_vec() }
    }

    /// `true` if the filter can never refuse anyone.
    pub fn is_open(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Admit or refuse `ip`.
    pub fn check(&self, ip: IpAddr) -> Result<(), Denial> {
        if self.is_open() {
            return Ok(());
        }
        let ip = canonical(ip);
        if contains(&self.deny, ip) {
            return Err(Denial::Denied);
        }
        if !self.allow.is_empty() && !contains(&self.allow, ip) {
            return Err(Denial::NotAllowed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_empty_filter_admits_everyone() {
        let f = IpFilter::default();
        assert!(f.is_open());
        for a in ["1.2.3.4", "::1", "2001:db8::1", "::ffff:1.2.3.4"] {
            assert_eq!(f.check(ip(a)), Ok(()), "{a}");
        }
    }

    #[test]
    fn allow_lists_admit_only_their_members() {
        let f = IpFilter::new(&nets(&["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"]), &[]);
        for a in ["10.1.2.3", "10.255.255.255", "2001:db8::beef", "192.0.2.7"] {
            assert_eq!(f.check(ip(a)), Ok(()), "{a}");
        }
        for a in ["11.0.0.1", "192.0.2.8", "2001:db9::1", "::1"] {
            assert_eq!(f.check(ip(a)), Err(Denial::NotAllowed), "{a}");
        }
    }

    #[test]
    fn deny_beats_allow_and_works_alone() {
        let f = IpFilter::new(&nets(&["10.0.0.0/8"]), &nets(&["10.6.6.0/24"]));
        assert_eq!(f.check(ip("10.1.1.1")), Ok(()));
        assert_eq!(f.check(ip("10.6.6.6")), Err(Denial::Denied), "inside both: deny wins");
        let only_deny = IpFilter::new(&[], &nets(&["203.0.113.0/24", "2001:db8:bad::/48"]));
        assert_eq!(only_deny.check(ip("8.8.8.8")), Ok(()), "no allow list: everyone not denied is in");
        assert_eq!(only_deny.check(ip("203.0.113.200")), Err(Denial::Denied));
        assert_eq!(only_deny.check(ip("2001:db8:bad::1")), Err(Denial::Denied));
        assert_eq!(only_deny.check(ip("2001:db8:600d::1")), Ok(()));
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_sidestep_an_ipv4_rule() {
        let deny = IpFilter::new(&[], &nets(&["203.0.113.0/24"]));
        assert_eq!(deny.check(ip("::ffff:203.0.113.9")), Err(Denial::Denied), "same client, other socket family");
        let allow = IpFilter::new(&nets(&["198.51.100.0/24"]), &[]);
        assert_eq!(allow.check(ip("::ffff:198.51.100.5")), Ok(()));
        assert_eq!(allow.check(ip("::ffff:198.51.101.5")), Err(Denial::NotAllowed));
        // …but a real IPv6 address is not confused with one.
        assert_eq!(canonical(ip("2001:db8::1")), ip("2001:db8::1"));
        assert_eq!(canonical(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical(ip("::1")), ip("::1"));
    }

    #[test]
    fn host_routes_and_default_routes_behave() {
        assert_eq!(IpFilter::new(&nets(&["0.0.0.0/0"]), &[]).check(ip("9.9.9.9")), Ok(()));
        assert_eq!(
            IpFilter::new(&nets(&["0.0.0.0/0"]), &[]).check(ip("2001:db8::1")),
            Err(Denial::NotAllowed),
            "v4 default route ≠ v6"
        );
        assert_eq!(IpFilter::new(&[], &nets(&["::/0"])).check(ip("2001:db8::1")), Err(Denial::Denied));
        assert_eq!(Denial::Denied.reason(), "deny");
        assert_eq!(Denial::NotAllowed.reason(), "not_allowed");
    }
}
