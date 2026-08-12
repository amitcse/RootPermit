//! Minimal Linux `SO_PEERCRED` adapter.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::AsRawFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
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
