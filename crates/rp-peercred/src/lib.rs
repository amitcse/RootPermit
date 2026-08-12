//! Minimal Linux Unix-domain socket adapter.
//!
//! The broker's requester boundary requires `SOCK_SEQPACKET`, not a byte
//! stream.  Keeping the small amount of Linux-specific unsafe code here keeps
//! the API and authority crates safe Rust while preserving packet boundaries
//! and kernel-authenticated `SO_PEERCRED` identities.

#![cfg(target_os = "linux")]
// Linux's ABI uses C integer widths for these syscall structures. Every cast
// below is bounded by the kernel constants or preceded by an explicit check.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc
)]

use std::ffi::CString;
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Linux `AF_UNIX` `SOCK_SEQPACKET` listener.
#[derive(Debug)]
pub struct SeqPacketListener {
    fd: OwnedFd,
}

/// One connected Linux `AF_UNIX` `SOCK_SEQPACKET` peer.
#[derive(Debug)]
pub struct SeqPacketConnection {
    fd: OwnedFd,
}

impl SeqPacketListener {
    /// Binds a filesystem socket.  Callers must have rejected an existing
    /// path and must apply the required mode/group before accepting peers.
    pub fn bind(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
        // SAFETY: the arguments are constants and the returned descriptor is
        // immediately transferred into `OwnedFd` on success.
        let raw =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly returned owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: every byte is initialized before the address is used, and
        // the length includes the terminating NUL in `sun_path`.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        if path.as_bytes_with_nul().len() > address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path is too long",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(path.as_bytes_with_nul()) {
            *destination = *source as libc::c_char;
        }
        let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
        let length = libc::socklen_t::try_from(offset + path.as_bytes_with_nul().len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path is too long"))?;
        // SAFETY: `address` is a valid initialized Unix-domain socket address
        // and `fd` remains open for this call.
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a bound Unix-domain socket and backlog is bounded.
        if unsafe { libc::listen(fd.as_raw_fd(), 32) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Accepts a connection with close-on-exec already set.
    pub fn accept(&self) -> io::Result<SeqPacketConnection> {
        // SAFETY: no peer address is requested and the accepted descriptor is
        // transferred to `OwnedFd` immediately on success.
        let raw = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is an owned descriptor returned by `accept4`.
        Ok(SeqPacketConnection {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }
}

impl SeqPacketConnection {
    /// Connects to a filesystem `SOCK_SEQPACKET` listener. This is used by the
    /// unprivileged CLI and integration harness; it has no authority-bearing
    /// parameters because the server derives identity with `SO_PEERCRED`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
        // SAFETY: constants are valid and ownership transfers into `OwnedFd`.
        let raw =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is freshly owned on success.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: fully initialized before use.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        if path.as_bytes_with_nul().len() > address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path is too long",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(path.as_bytes_with_nul()) {
            *destination = *source as libc::c_char;
        }
        let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
        let length = libc::socklen_t::try_from(offset + path.as_bytes_with_nul().len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path is too long"))?;
        // SAFETY: the address points to initialized Unix-domain data and `fd`
        // remains live across the call.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl AsRawFd for SeqPacketConnection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

impl SeqPacketConnection {
    /// Receives one complete packet.  Oversize or truncated packets fail
    /// rather than being interpreted as a valid prefix followed by a future
    /// frame.
    pub fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Linux returns the full datagram length with `MSG_TRUNC`, even if the
        // supplied buffer is shorter.  That lets the caller reject it before
        // CBOR decoding.
        // SAFETY: `buffer` is valid writable memory for its declared length and
        // the connection remains open throughout the syscall.
        let received = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = usize::try_from(received)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative packet length"))?;
        if received > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated seqpacket frame",
            ));
        }
        Ok(received)
    }

    /// Sends one complete packet.  `SOCK_SEQPACKET` preserves this message as
    /// a unit; a partial write is treated as a transport failure.
    pub fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: `packet` is valid readable memory and the descriptor remains
        // open throughout the syscall.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).ok() != Some(packet.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial seqpacket write",
            ));
        }
        Ok(())
    }
}

pub fn get(socket: &impl AsRawFd) -> io::Result<Credentials> {
    let mut value = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output pointers reference initialized, correctly sized
    // stack values and the borrowed socket remains open throughout this call.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut value).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() || value.pid < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SO_PEERCRED response",
        ));
    }
    Ok(Credentials {
        pid: value.pid as u32,
        uid: value.uid,
        gid: value.gid,
    })
}
