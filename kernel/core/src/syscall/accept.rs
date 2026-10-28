// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::file::{
        CreationFlags, StatusFlags,
        file_table::{FdFlags, FileDesc, RawFileDesc, get_file_fast},
    },
    prelude::*,
    util::net::write_socket_addr_to_user,
};

pub(super) fn sys_accept(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("sockfd = {sockfd}, sockaddr_ptr = 0x{sockaddr_ptr:x}, addrlen_ptr = 0x{addrlen_ptr:x}");

    do_accept(sockfd, sockaddr_ptr, addrlen_ptr, Flags::empty(), ctx)
}

pub(super) fn sys_accept4(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    flags: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("raw flags = 0x{:x}", flags);
    let flags = Flags::from_bits(flags)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid accept4 flags"))?;
    debug!(
        "sockfd = {}, sockaddr_ptr = 0x{:x}, addrlen_ptr = 0x{:x}, flags = {:?}",
        sockfd, sockaddr_ptr, addrlen_ptr, flags
    );

    do_accept(sockfd, sockaddr_ptr, addrlen_ptr, flags, ctx)
}

fn do_accept(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    flags: Flags,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let fd_flags = if flags.contains(Flags::SOCK_CLOEXEC) {
        FdFlags::CLOEXEC
    } else {
        FdFlags::empty()
    };

    // Reserve before dequeuing, as Linux does: `accept` removes the connection
    // from the listen queue, so a later failure would drop it.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/net/socket/accept.c#L40-L60>
    let reserved_fd = {
        let file_table = ctx.thread_local.borrow_file_table();
        file_table.unwrap().write().reserve(fd_flags)?
    };

    let result = accept_into_reserved(
        sockfd,
        sockaddr_ptr,
        addrlen_ptr,
        flags.contains(Flags::SOCK_NONBLOCK),
        reserved_fd,
        fd_flags,
        ctx,
    );

    if result.is_err() {
        let mut file_table_ref = ctx.thread_local.borrow_file_table_mut();
        let mut file_table_locked = file_table_ref.unwrap().write();
        file_table_locked.close_file(reserved_fd);
    }

    result?;
    Ok(SyscallReturn::Return(reserved_fd.into()))
}

/// Accepts into `reserved_fd`.
fn accept_into_reserved(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    is_nonblocking: bool,
    reserved_fd: FileDesc,
    fd_flags: FdFlags,
    ctx: &Context,
) -> Result<()> {
    let mut file_table = ctx.thread_local.borrow_file_table_mut();

    let (connected_socket, socket_addr) = {
        let file = get_file_fast!(&mut file_table, sockfd.try_into()?);
        let socket = file.as_socket_or_err()?;
        socket
            .accept(is_nonblocking)
            .map_err(|err| match err.error() {
                // FIXME: `accept` should not be restarted if a timeout has been set on the socket using `setsockopt`.
                Errno::EINTR => Error::new(Errno::ERESTARTSYS),
                _ => err,
            })?
    };

    if sockaddr_ptr != 0 {
        write_socket_addr_to_user(&socket_addr, sockaddr_ptr, addrlen_ptr)?;
    }

    file_table
        .unwrap()
        .write()
        .install(reserved_fd, connected_socket);
    Ok(())
}

bitflags! {
    struct Flags: u32 {
        const SOCK_NONBLOCK = NONBLOCK;
        const SOCK_CLOEXEC = CLOEXEC;
    }
}

const NONBLOCK: u32 = StatusFlags::O_NONBLOCK.bits();
const CLOEXEC: u32 = CreationFlags::O_CLOEXEC.bits();
