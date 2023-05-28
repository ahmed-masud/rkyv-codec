use std::{path::{PathBuf, Path}, fmt::Debug};

mod codec;
mod meta;
mod wrappers;

#[derive(Debug, Clone)]
pub struct AiFs {
    pub root: PathBuf,
}

impl AiFs {
    pub fn new<Partial>(root: Partial, _: &str, _: Option<String>) -> Self
    where
        Partial: AsRef<Path> + std::fmt::Debug,
    {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }
}

pub trait BackStore: Debug + Clone {
    fn metadir_path<Partial>(&self, partial: Partial) -> Result<PathBuf, i32>
    where
        Partial: AsRef<Path> + std::fmt::Debug;

    fn highest_path<Partial>(&self, partial: Partial) -> Result<PathBuf, i32>
        where
            Partial: AsRef<Path> + std::fmt::Debug;
    
}

impl BackStore for AiFs {
    fn metadir_path<Partial>(&self, partial: Partial) -> Result<PathBuf, i32>
    where
        Partial: AsRef<Path> + std::fmt::Debug,
    {
        Ok(PathBuf::from("/tmp/foo/meta").join(partial))
    }

    fn highest_path<Partial>(&self, partial: Partial) -> Result<PathBuf, i32>
            where
                Partial: AsRef<Path> + std::fmt::Debug {
        Ok(PathBuf::from("/tmp/foo/highest").join(partial))
    }

}
