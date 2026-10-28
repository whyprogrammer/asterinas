// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    fs::file::{
        FileLike,
        file_table::{FdFlags, RawFileDesc},
    },
    net::socket::unix::{UnixDatagramSocket, UnixStreamSocket},
    prelude::*,
    util::net::{CSocketAddrFamily, Protocol, SOCK_TYPE_MASK, SockFlags, SockType},
};

pub(super) fn sys_socketpair(
    domain: i32,
    type_: i32,
    protocol: i32,
    sv: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let domain = CSocketAddrFamily::try_from(domain)?;
    let sock_type = SockType::try_from(type_ & SOCK_TYPE_MASK)?;
    let sock_flags = SockFlags::from_bits_truncate(type_ & !SOCK_TYPE_MASK);
    let protocol = Protocol::try_from(protocol)?;
    debug!(
        "domain = {:?}, sock_type = {:?}, sock_flags = {:?}, protocol = {:?}",
        domain, sock_type, sock_flags, protocol
    );

    macro_rules! file_pair {
        ($expr:expr) => {{
            let (socket_a, socket_b) = $expr;
            (socket_a as Arc<dyn FileLike>, socket_b as Arc<dyn FileLike>)
        }};
    }

    let nonblocking = sock_flags.contains(SockFlags::SOCK_NONBLOCK);
    let (socket_a, socket_b) = match (domain, sock_type) {
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_STREAM) => {
            file_pair!(UnixStreamSocket::new_pair(nonblocking, sock_type))
        }
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_SEQPACKET) => {
            file_pair!(UnixStreamSocket::new_pair(nonblocking, sock_type))
        }
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_RAW | SockType::SOCK_DGRAM) => {
            file_pair!(UnixDatagramSocket::new_pair(nonblocking))
        }
        _ => return_errno_with_message!(
            Errno::EAFNOSUPPORT,
            "creating a socket pair for this family is not supported"
        ),
    };

    let fd_flags = if sock_flags.contains(SockFlags::SOCK_CLOEXEC) {
        FdFlags::CLOEXEC
    } else {
        FdFlags::empty()
    };

    // Reserve first, install after the copy, so a failed copy leaks nothing.
    let (fd_a, fd_b) = {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        file_table_locked.reserve_pair(fd_flags)?
    };

    let socket_fds = SocketFds(fd_a.into(), fd_b.into());
    if let Err(err) = ctx.user_space().write_val(sv, &socket_fds) {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        file_table_locked.close_file(fd_a);
        file_table_locked.close_file(fd_b);
        return Err(err.into());
    }

    {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        file_table_locked.install_pair(fd_a, socket_a, fd_b, socket_b);
    }

    Ok(SyscallReturn::Return(0))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SocketFds(RawFileDesc, RawFileDesc);
