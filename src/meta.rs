use std::{
    ffi::{CString, OsStr, OsString},
    marker::PhantomData,
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    ptr,
    time::SystemTime, fmt::Formatter,
};

use super::{AiFs, BackStore};
use crate::{codec::ser::CodecSerializer, wrappers};
use ::nix::unistd::{Group, User};
use file_lock::{FileLock, FileOptions};
use libc::EBUSY;

use rkyv::{
    ser::serializers::AllocSerializer,
    with::AsString,
    AlignedVec, Archive, Deserialize, Serialize,
};

/// Metadata Entry Hash
#[derive(Debug, Clone, PartialEq, Eq, Copy, Archive, Serialize, Deserialize)]
pub enum EntryHash {
    SHA2([u8; 32]),
    SHA3([u8; 32]),
}

/// Extended attributes

/// Entry in the metadata history of a file or directory.
/// this is used to track the previous stats of a file or directory
/// when it is modified.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub struct EntryMetaData<B = AiFs>
where
    B: BackStore + std::fmt::Debug ,
{
    #[with(AsString)]
    pub name: OsString,
    #[with(AsString)]
    pub parent: PathBuf,
    #[with(crate::codec::FileStatCodec)]
    pub stats: ::nix::sys::stat::FileStat,
    #[with(crate::codec::UserCodec)]
    pub owner: User,
    #[with(crate::codec::GroupCodec)]
    pub group: Group,
    pub timestamp: u64,

    pub xattrs: Option<Vec<(CString, Vec<u8>)>>,

    #[with(rkyv::with::Skip)]
    pub _fs: PhantomData<B>,
}

impl std::fmt::Debug for ArchivedEntryMetaData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivedEntryMetaData")
            .field("name", &self.name)
            .field("parent", &self.parent)
            .field("stats", &self.stats)
            .field("owner", &self.owner)
            .field("group", &self.group)
            .field("timestamp", &self.timestamp)
            .field("xattrs", &self.xattrs)
            .finish()
    }
}

impl<B> EntryMetaData<B>
where
    B: BackStore + std::fmt::Debug + Clone,
{
    pub fn new<Partial>(fs: &B, parent: Partial, name: &OsStr) -> Result<Self, i32>
    where
        Partial: AsRef<Path>,
    {
        let parent = parent.as_ref();
        let name = name.to_os_string();
        let path = parent.join(&name);
        let path = fs.highest_path(path)?;
        let path = path.as_path();
        let stats = ::nix::sys::stat::stat(path).map_err(|e| e as i32)?;
        let user = nix::unistd::Uid::from_raw(stats.st_uid);
        let mut owner = ::nix::unistd::User::from_uid(user)
            .map_err(|e| e as i32)?
            .unwrap_or_else(|| ::nix::unistd::User {
                uid: stats.st_uid.into(),
                passwd: unsafe { CString::from_raw(ptr::null_mut()) },
                name: "unknown".to_string(),
                gid: stats.st_gid.into(),
                shell: PathBuf::new(),
                gecos: unsafe { CString::from_raw(ptr::null_mut()) },
                dir: PathBuf::new(),
            });
        let group = nix::unistd::Gid::from_raw(stats.st_gid);
        let mut group = ::nix::unistd::Group::from_gid(group)
            .map_err(|e| e as i32)?
            .unwrap_or_else(|| ::nix::unistd::Group {
                gid: stats.st_gid.into(),
                name: "unknown".to_string(),
                passwd: unsafe { CString::from_raw(ptr::null_mut()) },
                mem: Vec::new(),
            });
        // this should NEVER ever panic! but if it does we want to stop all file i/o
        owner.passwd = CString::from_vec_with_nul(b"x\0".to_vec()).unwrap();
        group.passwd = CString::from_vec_with_nul(b"x\0".to_vec()).unwrap();

        let xattrs_len = wrappers::listxattr(path, &mut [0; 0]).unwrap_or(0);
        let xattrs = if xattrs_len > 0 {
            let mut xattrs = vec![0; xattrs_len];
            wrappers::listxattr(path, &mut xattrs).unwrap();
            let xattrs = xattrs
                .split(|x| *x == 0)
                .map(|x| CString::from_vec_with_nul(x.to_vec()).ok())
                .collect::<Vec<_>>();
            let xattrs = xattrs
                .into_iter()
                .flatten()
                .map(|x| {
                    let _x = OsString::from_vec(x.clone().into_bytes());
                    let value = wrappers::getxattr(path, &_x).unwrap_or(Vec::new());
                    (x, value)
                })
                .collect::<Vec<_>>();
            Some(xattrs)
        } else {
            None
        };

        // time when metadata was created
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(Self {
            name,
            parent: parent.into(),
            stats,
            owner,
            group,
            timestamp,
            xattrs,
            _fs: PhantomData::default(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, i32> {
        let bytes: AlignedVec = CodecSerializer::<AllocSerializer<1024>>::encode(self)
            .unwrap()
            .into_serializer()
            .into_inner();
        Ok(bytes.to_vec())
    }
    /// write the metadata to the backstore
    /// we consume self because we don't want to write the same metadata twice
    // TODO: create a timeout for the lock (using parking_lot::Mutex)
    pub fn write(self, fs: &B) -> Result<(), i32> {
        let partial = self.parent.as_path().join(&self.name);
        let path = fs.metadir_path(partial)?;
        std::fs::create_dir_all(&path).map_err(|e| e.raw_os_error().unwrap_or(-1))?;
        let path = path.join(".metadata");
        let _history_path = path.join(".metadata.history");
        let opts = FileOptions::new()
            .write(true)
            .create(true)
            .append(false)
            .read(true);

        let mut _lock =
            FileLock::lock(&path, true, opts).map_err(|e| e.raw_os_error().unwrap_or(EBUSY))?;

        // _lock.file.write_all(buf.as_ref()).map_err(|e| e.raw_os_error().unwrap_or(-1))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MetaDataHistory<B>
where
    B: BackStore + std::fmt::Debug + Clone,
{
    pub name: String,
    pub hash: EntryHash,
    pub emd: Vec<EntryMetaData<B>>,
}

#[cfg(test)]
mod tests {
    use rkyv::archived_root;

    use super::*;

    #[test]
    fn test_metadata() {
        let fs = AiFs::new("/tmp/aifs", "/tmp/lower", None);
        let emd = EntryMetaData::new(&fs, "/", OsStr::new("test.txt")).unwrap();
        eprintln!("{:?}", emd);
        let bytes = emd.to_bytes().unwrap();
        let emd2 = unsafe { archived_root::<EntryMetaData>(bytes.as_slice()) };
        eprintln!("{:?}", emd2);

        let emd2: EntryMetaData =
            ArchivedEntryMetaData::deserialize(&emd2, &mut rkyv::Infallible).unwrap();
        eprintln!("{:?}", emd2);
    }

    #[test]
    fn test_nix_user() {
        use nix::unistd::{Uid, User};
        // Returns an Result<Option<User>>, thus the double unwrap.
        let res = User::from_uid(Uid::from_raw(1000)).unwrap().unwrap();
        assert_eq!(res.name, "masud");
    }
}
