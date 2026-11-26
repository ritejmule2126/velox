//! Socket construction and tuning (`SO_REUSEPORT`, `TCP_NODELAY`, keep-alive).

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::time::Duration;
use tokio::net::TcpStream;

fn new_socket(addr: SocketAddr, ty: Type, proto: Protocol, reuse_port: bool) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(proto))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))))]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(all(unix, not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin")))))]
    let _ = reuse_port;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        // Dual-stack: let `[::]` accept IPv4-mapped connections too.
        let _ = socket.set_only_v6(false);
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Bind a non-blocking TCP listener.
pub fn bind_tcp(addr: SocketAddr, backlog: i32, reuse_port: bool) -> io::Result<StdTcpListener> {
    let socket = new_socket(addr, Type::STREAM, Protocol::TCP, reuse_port)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(socket.into())
}

/// Bind a non-blocking UDP socket with enlarged buffers (for QUIC).
pub fn bind_udp(addr: SocketAddr, reuse_port: bool) -> io::Result<StdUdpSocket> {
    let socket = new_socket(addr, Type::DGRAM, Protocol::UDP, reuse_port)?;
    // Best effort: large buffers absorb bursts; the OS may clamp them.
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Apply `TCP_NODELAY` and OS keep-alive probes to an accepted connection.
pub fn tune_accepted(stream: &TcpStream, nodelay: bool) {
    let _ = stream.set_nodelay(nodelay);
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(15));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reuse_port_allows_parallel_listeners_on_one_port() {
        let first = bind_tcp("127.0.0.1:0".parse().unwrap(), 128, true).unwrap();
        let addr = first.local_addr().unwrap();
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            let second = bind_tcp(addr, 128, true).unwrap();
            assert_eq!(second.local_addr().unwrap(), addr);
        }
        let no_reuse = bind_tcp(addr, 128, false);
        assert!(no_reuse.is_err(), "without SO_REUSEPORT a second bind must fail");
    }

    #[tokio::test]
    async fn udp_binds_and_reports_port() {
        let s = bind_udp("127.0.0.1:0".parse().unwrap(), false).unwrap();
        assert_ne!(s.local_addr().unwrap().port(), 0);
    }
}
