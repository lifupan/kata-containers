// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoint and restore framework for the Dragonball VMM.
//!
//! This module provides the ability to save and restore the complete state of a
//! virtual machine, including guest memory, vCPU registers, and all device states.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_derive::{Deserialize, Serialize};

/// Errors associated with checkpoint/restore operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// I/O error during checkpoint/restore.
    #[error("I/O error during checkpoint/restore: {0}")]
    Io(#[from] io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    /// VM is not in a valid state for checkpoint.
    #[error("VM is not in a valid state for checkpoint")]
    InvalidVmState,

    /// Failed to pause vCPUs.
    #[error("failed to pause vCPUs: {0}")]
    PauseVcpus(String),

    /// Failed to resume vCPUs.
    #[error("failed to resume vCPUs: {0}")]
    ResumeVcpus(String),

    /// Memory save/restore error.
    #[error("memory error: {0}")]
    Memory(String),

    /// Device state error.
    #[error("device state error: {0}")]
    DeviceState(String),

    /// vCPU state error.
    #[error("vCPU state error: {0}")]
    VcpuState(String),

    /// Checkpoint directory error.
    #[error("checkpoint directory error: {0}")]
    CheckpointDir(String),
}

/// Result type for checkpoint/restore operations.
pub type Result<T> = std::result::Result<T, CheckpointError>;

/// Metadata about a checkpoint snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Version of the checkpoint format.
    pub version: u32,
    /// Timestamp when the checkpoint was created (Unix epoch in microseconds).
    pub timestamp_us: u64,
    /// Number of vCPUs in the VM.
    pub vcpu_count: u8,
    /// Memory size in MiB.
    pub mem_size_mib: usize,
}

impl Default for CheckpointMetadata {
    fn default() -> Self {
        CheckpointMetadata {
            version: 1,
            timestamp_us: 0,
            vcpu_count: 0,
            mem_size_mib: 0,
        }
    }
}

/// Manages checkpoint directory structure and file operations.
pub struct CheckpointManager {
    /// Root directory for the checkpoint.
    checkpoint_dir: PathBuf,
}

impl CheckpointManager {
    /// File name for the checkpoint metadata.
    pub const METADATA_FILE: &'static str = "metadata.json";
    /// File name for the VM state.
    pub const VM_STATE_FILE: &'static str = "vm_state.json";
    /// File name for the device manager state.
    pub const DEVICE_STATE_FILE: &'static str = "device_state.json";
    /// File name for the vCPU state.
    pub const VCPU_STATE_FILE: &'static str = "vcpu_state.json";
    /// File name for the guest memory dump.
    pub const MEMORY_FILE: &'static str = "guest_memory.bin";

    /// Create a new CheckpointManager for the given directory.
    pub fn new<P: AsRef<Path>>(checkpoint_dir: P) -> Result<Self> {
        let dir = checkpoint_dir.as_ref().to_path_buf();
        Ok(CheckpointManager {
            checkpoint_dir: dir,
        })
    }

    /// Prepare the checkpoint directory (create if not exists).
    pub fn prepare_checkpoint_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.checkpoint_dir).map_err(|e| {
            CheckpointError::CheckpointDir(format!(
                "failed to create checkpoint directory {:?}: {}",
                self.checkpoint_dir, e
            ))
        })
    }

    /// Get the path for a specific checkpoint file.
    pub fn file_path(&self, filename: &str) -> PathBuf {
        self.checkpoint_dir.join(filename)
    }

    /// Save serializable state to a JSON file.
    pub fn save_state<T: serde::Serialize>(&self, filename: &str, state: &T) -> Result<()> {
        let path = self.file_path(filename);
        let json = serde_json::to_string_pretty(state)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Load serializable state from a JSON file.
    pub fn load_state<T: serde::de::DeserializeOwned>(&self, filename: &str) -> Result<T> {
        let path = self.file_path(filename);
        let mut file = File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let state = serde_json::from_str(&contents)?;
        Ok(state)
    }

    /// Save raw bytes to a file.
    pub fn save_raw(&self, filename: &str, data: &[u8]) -> Result<()> {
        let path = self.file_path(filename);
        let mut file = File::create(&path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }

    /// Get the checkpoint directory path.
    pub fn checkpoint_dir(&self) -> &Path {
        &self.checkpoint_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_metadata_default() {
        let meta = CheckpointMetadata::default();
        assert_eq!(meta.version, 1);
        assert_eq!(meta.timestamp_us, 0);
        assert_eq!(meta.vcpu_count, 0);
        assert_eq!(meta.mem_size_mib, 0);
    }

    #[test]
    fn test_checkpoint_metadata_serialize() {
        let meta = CheckpointMetadata {
            version: 1,
            timestamp_us: 12345,
            vcpu_count: 4,
            mem_size_mib: 256,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let restored: CheckpointMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.version, meta.version);
        assert_eq!(restored.timestamp_us, meta.timestamp_us);
        assert_eq!(restored.vcpu_count, meta.vcpu_count);
        assert_eq!(restored.mem_size_mib, meta.mem_size_mib);
    }

    #[test]
    fn test_checkpoint_manager_file_path() {
        let mgr = CheckpointManager::new("/tmp/test_checkpoint").unwrap();
        assert_eq!(
            mgr.file_path("vm_state.json"),
            PathBuf::from("/tmp/test_checkpoint/vm_state.json")
        );
    }

    #[test]
    fn test_checkpoint_manager_save_load() {
        let dir = "/tmp/dragonball_test_checkpoint";
        let _ = fs::remove_dir_all(dir);

        let mgr = CheckpointManager::new(dir).unwrap();
        mgr.prepare_checkpoint_dir().unwrap();

        let meta = CheckpointMetadata {
            version: 1,
            timestamp_us: 99999,
            vcpu_count: 2,
            mem_size_mib: 128,
        };

        mgr.save_state(CheckpointManager::METADATA_FILE, &meta)
            .unwrap();
        let loaded: CheckpointMetadata =
            mgr.load_state(CheckpointManager::METADATA_FILE).unwrap();
        assert_eq!(loaded.version, meta.version);
        assert_eq!(loaded.vcpu_count, meta.vcpu_count);

        let _ = fs::remove_dir_all(dir);
    }
}
