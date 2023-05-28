#![allow(non_camel_case_types)]
use std::ffi::CString;

/// Fallable Serializer for libc types

pub mod ser {
    use std::{alloc::Layout, ptr::NonNull};

    use rkyv::{
        ser::{ ScratchSpace, Serializer},
        with::{AsStringError},
        Fallible,
    };
    pub struct CodecSerializer<S> {
        pub inner: S,
    }

    impl<S> CodecSerializer<S> {
        pub fn new(inner: S) -> Self {
            Self { inner }
        }

        pub fn into_inner(self) -> S {
            self.inner
        }
    }

    impl<S: Serializer> Serializer for CodecSerializer<S> {
        #[inline]
        fn pos(&self) -> usize {
            self.inner.pos()
        }

        #[inline]
        fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.inner.write(bytes).map_err(CodecSerializerError::Inner)
        }
    }

    impl<S: Fallible + Serializer + Default> CodecSerializer<S>
    where
        <S as Fallible>::Error: std::fmt::Debug, // + From<CodecSerializerError<CodecSerializerError<<S as Fallible>::Error>>>
    {
        pub fn encode<T>(value: &T) -> Result<S, <S as Fallible>::Error>
        where
            T: rkyv::Serialize<CodecSerializer<S>>,
        {
            let mut serializer = CodecSerializer::<S>::default();
            serializer.serialize_value(value).unwrap();
            Ok(serializer.into_inner())
        }
    }

    impl<S: Default> Default for CodecSerializer<S> {
        fn default() -> Self {
            Self::new(S::default())
        }
    }

    impl<S: Fallible> Fallible for CodecSerializer<S> {
        type Error = CodecSerializerError<S::Error>;
    }

    impl<S: ScratchSpace> ScratchSpace for CodecSerializer<S> {
        unsafe fn push_scratch(&mut self, layout: Layout) -> Result<NonNull<[u8]>, Self::Error> {
            self.inner
                .push_scratch(layout)
                .map_err(CodecSerializerError::Inner)
        }

        unsafe fn pop_scratch(
            &mut self,
            ptr: NonNull<u8>,
            layout: Layout,
        ) -> Result<(), Self::Error> {
            self.inner
                .pop_scratch(ptr, layout)
                .map_err(CodecSerializerError::Inner)
        }
    }

    // This is our new error type. It has one variant for errors from the inner serializer, and one
    // variant for AsStringErrors.
    #[derive(Debug)]
    pub enum CodecSerializerError<E> {
        Inner(E),
        AsStringError,
    }

    impl<E> From<AsStringError> for CodecSerializerError<E> {
        fn from(_: AsStringError) -> Self {
            CodecSerializerError::AsStringError
        }
    }
}

// use nix::unistd::{Uid, Gid};
// use rkyv::{Archive, Serialize, Deserialize, Infallible};
use rkyv::with::{ArchiveWith, DeserializeWith};
use rkyv_with::{ArchiveWith, DeserializeWith};

#[derive(Debug, Clone, rkyv::Archive, ArchiveWith)]
#[archive_with(from(::nix::sys::stat::FileStat))]
#[archive_attr(derive(Debug))]
pub struct FileStatCodec {
    pub st_dev: ::libc::dev_t,
    pub st_ino: ::libc::ino_t,
    pub st_nlink: ::libc::nlink_t,
    pub st_mode: ::libc::mode_t,
    pub st_uid: ::libc::uid_t,
    pub st_gid: ::libc::gid_t,
    #[archive_with(getter = "FileStatCodec::__get_pad0")]
    __pad0: ::libc::c_int,
    pub st_rdev: ::libc::dev_t,
    pub st_size: ::libc::off_t,
    pub st_blksize: ::libc::blksize_t,
    pub st_blocks: ::libc::blkcnt_t,
    pub st_atime: ::libc::time_t,
    pub st_atime_nsec: i64,
    pub st_mtime: ::libc::time_t,
    pub st_mtime_nsec: i64,
    pub st_ctime: ::libc::time_t,
    pub st_ctime_nsec: i64,
    #[archive_with(getter = "FileStatCodec::__get_unused")]
    __unused: [i64; 3],
}

impl FileStatCodec {
    fn __get_pad0(_: &libc::stat) -> ::libc::c_int {
        0
    }

    fn __get_unused(_: &libc::stat) -> [i64; 3] {
        [0; 3]
    }
}

impl From<FileStatCodec> for ::libc::stat {
    fn from(stat: FileStatCodec) -> Self {
        let mut stat: ::libc::stat = unsafe { ::std::mem::transmute(stat) };
        stat.st_atime_nsec = stat.st_atime_nsec;
        stat.st_mtime_nsec = stat.st_mtime_nsec;
        stat.st_ctime_nsec = stat.st_ctime_nsec;
        stat
    }
}

/// Serialize and Deserialize User
#[derive(Debug, Clone, rkyv::Archive, ArchiveWith)]
#[archive_with(from(::nix::unistd::User))]
#[archive_attr(derive(Debug))]
pub struct UserCodec {
    /// Username
    pub name: String,
    /// User password (probably hashed)
    pub passwd: CString,
    /// User ID
    #[archive_with(from(::nix::unistd::Uid))]
    pub uid: UidCodec,
    /// Group ID
    #[archive_with(from(::nix::unistd::Gid))]
    pub gid: GidCodec,
    /// User information
    #[cfg(not(all(target_os = "android", target_pointer_width = "32")))]
    pub gecos: CString,
    /// Home directory
    #[archive_with(from(std::path::PathBuf), via(rkyv::with::AsString))]
    pub dir: String,
    /// Path to shell
    #[archive_with(from(std::path::PathBuf), via(rkyv::with::AsString))]
    pub shell: String,
}

/// Serialize and Deserialize Group
#[derive(Debug, Clone, rkyv::Archive, ArchiveWith)]
#[archive_with(from(::nix::unistd::Group))]
#[archive_attr(derive(Debug))]
pub struct GroupCodec {
    /// Group name
    pub name: String,
    /// Group password (probably hashed)
    pub passwd: CString,
    /// Group ID
    #[archive_with(from(::nix::unistd::Gid))]
    pub gid: GidCodec,
    /// Group members
    pub mem: Vec<String>,
}

#[derive(Debug, Clone, rkyv::Archive, ArchiveWith, DeserializeWith)]
#[archive_with(from(::nix::unistd::Gid))]
#[archive_attr(derive(Debug))]
pub struct GidCodec(::libc::gid_t);

#[derive(Debug, Clone, rkyv::Archive, ArchiveWith, DeserializeWith)]
#[archive_with(from(::nix::unistd::Uid))]
#[archive_attr(derive(Debug))]
pub struct UidCodec(::libc::uid_t);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_stat_codec() {
        let stat = FileStatCodec {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: 0,
            st_atime_nsec: 0,
            st_mtime: 0,
            st_mtime_nsec: 0,
            st_ctime: 0,
            st_ctime_nsec: 0,
            __unused: [0; 3],
        };
        let stat: ::libc::stat = stat.into();
        assert_eq!(stat.st_atime_nsec, 0);
        assert_eq!(stat.st_mtime_nsec, 0);
        assert_eq!(stat.st_ctime_nsec, 0);
    }
}
