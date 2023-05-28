// Libc Wrappers :: Safe wrappers around system calls.
//
// Copyright (C) 2023 saf.ai Inc.
//

// use super::extras;
use std::ffi::{CString, OsStr, };
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[allow(unused_imports)]
pub(crate) mod consts {
    #[allow(unused_imports)]
    pub(crate) use ::libc::{
        c_char, c_int, c_long, c_longlong, c_short, c_uchar, c_uint, c_ulong, c_ulonglong,
        c_ushort, c_void, dev_t, gid_t, ino_t, mode_t, off_t, pid_t, ssize_t, uid_t, EACCES,
        EAGAIN, EALREADY, EBUSY, EEXIST, EFAULT, EINPROGRESS, EINTR, EINVAL, EIO, EISDIR, EMFILE,
        EMLINK, ENFILE, ENODEV, ENOENT, ENOMEM, ENOSPC, ENOSYS, ENOTDIR, ENOTTY, EPERM, EPIPE,
        EROFS, ESPIPE, ESRCH, EWOULDBLOCK, EXDEV, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY,
        O_EXCL, O_LARGEFILE, O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR,
        O_RSYNC, O_SYNC, O_TMPFILE, O_TRUNC, O_WRONLY,
    };
}

use self::consts::*;

macro_rules! into_cstring {
    ($path:expr, $syscall:expr) => {
        match CString::new($path.as_os_str().as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                return Err(EINVAL);
            }
        }
    };
}

trait AsOsStr {
    fn as_os_str(&self) -> &OsStr;
}
impl AsOsStr for Path {
    fn as_os_str(&self) -> &OsStr {
        self.as_ref()
    }
}

impl AsOsStr for OsStr {
    fn as_os_str(&self) -> &OsStr {
        self
    }
}


macro_rules! syscall_errno {
    ($syscall:expr,return $rv:expr) => {{
        let rv = unsafe { $syscall };
        if rv < 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        $rv
    }};

    (return $syscall:expr) => {{
        let rv = unsafe { $syscall };
        if (rv as libc::c_int) < 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        rv
    }};
    ($syscall:expr) => {{
        let rv = unsafe { $syscall };
        if rv < 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        Ok(())
    }};
}

#[inline]
pub fn getxattr(path: &Path, name: &OsStr) -> Result<Vec<u8>, libc::c_int> {
    let path_c = into_cstring!(path, "getxattr");
    let name_c = into_cstring!(name, "getxattr");

    let mut buf: [libc::c_char; libc::PATH_MAX as usize] = unsafe { mem::zeroed() };
    syscall_errno! {
        libc::getxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        ),
        return Ok(Vec::from(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes()))
    }
}


#[inline]
pub fn listxattr(path: &Path, buf: &mut [u8]) -> Result<usize, libc::c_int> {
    let path_c = into_cstring!(path, "llistxattr");

    Ok(syscall_errno!(
        return libc::listxattr(
            path_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    ) as usize)
}

