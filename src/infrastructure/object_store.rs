use sha2::{Digest, Sha256};
use std::{
    env,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct LocalObjectStore {
    root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct StoredObject {
    pub hash: String,
    pub byte_size: i64,
}

impl LocalObjectStore {
    pub fn from_env() -> Self {
        let root = env::var("LOCAL_OBJECT_STORE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./var/object-store"));

        std::fs::create_dir_all(root.join("tmp")).expect("Failed to create object store tmp dir");
        std::fs::create_dir_all(root.join("objects")).expect("Failed to create object store dir");

        Self { root }
    }

    pub fn absolute_path(&self, storage_path: &str) -> PathBuf {
        self.root.join(storage_path)
    }

    pub async fn begin_write(&self) -> Result<PendingObjectWrite, ObjectStoreError> {
        let tmp_path = self.tmp_path();
        let file = File::create(&tmp_path).await?;

        Ok(PendingObjectWrite {
            tmp_path,
            file,
            hasher: Sha256::new(),
            byte_size: 0,
        })
    }

    pub async fn finish_write(
        &self,
        mut pending: PendingObjectWrite,
    ) -> Result<StoredObject, ObjectStoreError> {
        pending.file.flush().await?;
        drop(pending.file);

        let hash = hex::encode(pending.hasher.finalize());
        let storage_path = storage_path_for_hash(&hash);
        let final_path = self.absolute_path(&storage_path);

        if fs::try_exists(&final_path).await? {
            let _ = fs::remove_file(&pending.tmp_path).await;
        } else {
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::rename(&pending.tmp_path, &final_path).await?;
        }

        Ok(StoredObject {
            hash,
            byte_size: pending.byte_size,
        })
    }

    fn tmp_path(&self) -> PathBuf {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        self.root
            .join("tmp")
            .join(format!("upload-{pid}-{counter}"))
    }
}

pub struct PendingObjectWrite {
    tmp_path: PathBuf,
    file: File,
    hasher: Sha256,
    byte_size: i64,
}

impl PendingObjectWrite {
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), ObjectStoreError> {
        self.file.write_all(chunk).await?;
        self.hasher.update(chunk);
        self.byte_size += chunk.len() as i64;
        Ok(())
    }
}

pub fn storage_path_for_hash(hash: &str) -> String {
    format!("objects/{}/{}/{}", &hash[0..2], &hash[2..4], &hash[4..])
}

#[derive(Debug)]
pub enum ObjectStoreError {
    Io,
}

impl From<std::io::Error> for ObjectStoreError {
    fn from(_error: std::io::Error) -> Self {
        Self::Io
    }
}
