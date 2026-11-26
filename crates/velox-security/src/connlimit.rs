//! Global and per-source-IP connection caps.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The process-wide cap was reached.
    #[error("global connection limit reached")]
    Global,
    /// This source already holds its maximum number of connections.
    #[error("per-IP connection limit reached")]
    PerIp,
}

/// Tracks open connections; permits release their slot on drop.
#[derive(Debug, Default)]
pub struct ConnectionLimiter {
    total: AtomicUsize,
    per_ip: DashMap<IpAddr, usize>,
}

/// Aggregate IPv6 sources by /64 so address-space abuse cannot dodge the cap.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::V6(o.into())
            }
        },
        v4 => v4,
    }
}

impl ConnectionLimiter {
    /// An empty limiter.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Claim a slot for `ip`. A limit of `0` means unlimited.
    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        max_total: usize,
        max_per_ip: usize,
    ) -> Result<ConnectionPermit, Refused> {
        let prev = self.total.fetch_add(1, Ordering::AcqRel);
        if max_total != 0 && prev >= max_total {
            self.total.fetch_sub(1, Ordering::AcqRel);
            return Err(Refused::Global);
        }
        let key = bucket(ip);
        let mut entry = self.per_ip.entry(key).or_insert(0);
        if max_per_ip != 0 && *entry >= max_per_ip {
            drop(entry);
            self.total.fetch_sub(1, Ordering::AcqRel);
            return Err(Refused::PerIp);
        }
        *entry += 1;
        drop(entry);
        Ok(ConnectionPermit { limiter: Arc::clone(self), key })
    }

    /// Currently open connections.
    pub fn open(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// Distinct sources currently tracked.
    pub fn sources(&self) -> usize {
        self.per_ip.len()
    }
}

/// A claimed connection slot.
#[derive(Debug)]
pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    key: IpAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.total.fetch_sub(1, Ordering::AcqRel);
        // One shard lock: decrement, and drop the entry when it reaches zero.
        if let Entry::Occupied(mut slot) = self.limiter.per_ip.entry(self.key) {
            if *slot.get() <= 1 {
                slot.remove();
            } else {
                *slot.get_mut() -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_ip_and_global_caps_and_releases() {
        let l = ConnectionLimiter::new();
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        let p1 = l.try_acquire(a, 3, 2).unwrap();
        let _p2 = l.try_acquire(a, 3, 2).unwrap();
        assert_eq!(l.try_acquire(a, 3, 2).unwrap_err(), Refused::PerIp);
        let _p3 = l.try_acquire(b, 3, 2).unwrap();
        assert_eq!(l.try_acquire(b, 3, 2).unwrap_err(), Refused::Global);
        assert_eq!(l.open(), 3);
        drop(p1);
        assert_eq!(l.open(), 2);
        assert!(l.try_acquire(a, 3, 2).is_ok());
    }

    #[test]
    fn zero_means_unlimited_and_entries_are_reclaimed() {
        let l = ConnectionLimiter::new();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let permits: Vec<_> = (0..500).map(|_| l.try_acquire(ip, 0, 0).unwrap()).collect();
        assert_eq!(l.open(), 500);
        drop(permits);
        assert_eq!(l.open(), 0);
        assert_eq!(l.sources(), 0);
    }

    #[test]
    fn concurrent_acquire_release_never_leaks_or_underflows() {
        let l = ConnectionLimiter::new();
        let ips: Vec<IpAddr> = (1..=4).map(|i| format!("10.0.0.{i}").parse().unwrap()).collect();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let (l, ips) = (Arc::clone(&l), ips.clone());
                std::thread::spawn(move || {
                    for i in 0..5_000usize {
                        let ip = ips[(t + i) % ips.len()];
                        if let Ok(p) = l.try_acquire(ip, 0, 3) {
                            std::hint::black_box(&p);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(l.open(), 0, "every permit released");
        assert_eq!(l.sources(), 0, "every per-IP entry reclaimed");
    }

    #[test]
    fn ipv6_sources_share_a_slash_64() {
        let l = ConnectionLimiter::new();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff".parse().unwrap();
        let _p = l.try_acquire(a, 0, 1).unwrap();
        assert_eq!(l.try_acquire(b, 0, 1).unwrap_err(), Refused::PerIp);
    }
}
