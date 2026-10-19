//! Config-independent TCP listener Socket initialization shared by Server and Client.
use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Prevent another listener from overlapping a Windows IPv6 dual-stack port.
#[cfg(windows)]
fn set_exclusive_addr_use(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
    };

    let enabled = 1i32;
    let raw_socket = usize::try_from(socket.as_raw_socket()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Winsock socket handle out of range",
        )
    })?;
    // SAFETY: the socket owns a valid Winsock handle, and enabled is
    // readable for the duration of this synchronous setsockopt call.
    let result = unsafe {
        setsockopt(
            raw_socket,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast::<u8>(),
            i32::try_from(std::mem::size_of_val(&enabled)).expect("i32 size fits in i32"),
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Prepare an unbound TCP Socket with the requested IPv6-only policy.
///
/// Callers control any additional options, bind, listen, backlog and Tokio conversion.
pub fn prepare_tcp_listener_socket(
    addr: SocketAddr,
    ipv6_only: Option<bool>,
) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        if let Some(only_v6) = ipv6_only {
            socket.set_only_v6(only_v6)?;
        }
        // On Windows, omitting SO_REUSEADDR is not enough to prevent overlap
        // of a dual-stack wildcard listener with another IPv4 socket.
        #[cfg(windows)]
        if !socket.only_v6()? {
            set_exclusive_addr_use(&socket)?;
        }
    }
    Ok(socket)
}
