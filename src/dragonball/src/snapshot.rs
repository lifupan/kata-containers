// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot support for Dragonball VMM.
//!
//! This module implements checkpoint and restore functionality for the Dragonball
//! virtual machine monitor. It supports saving and restoring the VMM configuration
//! and guest memory state.
//!
//! # Snapshot format
//!
//! A snapshot consists of a directory containing two files:
//! - `vmm_state.json`: JSON-serialized [`MicrovmState`] (VMM configuration).
//! - `memory.bin`: Binary memory dump with the following layout:
//!   - 8-byte magic: `DBSNAP01`
//!   - u64 (LE): number of memory regions
//!   - For each region:
//!     - u64 (LE): guest physical start address
//!     - u64 (LE): region size in bytes
//!     - `size` bytes of raw memory contents
//!
//! # Note
//!
//! This implementation checkpoints VMM configuration and guest memory only.
//! vCPU register state and device state are not included in the snapshot; a
//! full execution-resume snapshot would require those as a future enhancement.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use serde_derive::{Deserialize, Serialize};
use vm_memory::{address::Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryRegion, MemoryRegionAddress};

use crate::address_space_manager::GuestAddressSpaceImpl;
use crate::vcpu::VcpuManagerError;
use crate::vm::VmConfigInfo;

/// Magic bytes written at the start of every memory snapshot file.
pub const SNAPSHOT_MAGIC: &[u8; 8] = b"DBSNAP01";

/// Name of the VMM state file inside a snapshot directory.
pub const VMM_STATE_FILE: &str = "vmm_state.json";
/// Name of the memory dump file inside a snapshot directory.
pub const MEMORY_FILE: &str = "memory.bin";

/// Configuration for snapshot create/restore operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Path to the snapshot directory.
    pub snapshot_path: String,
}

/// Serialisable VMM state captured during a snapshot.
///
/// Contains the information required to recreate the VM configuration when
/// restoring from a snapshot. Device state and vCPU register state are
/// intentionally omitted in the initial implementation.
#[derive(Debug, Serialize, Deserialize)]
pub struct MicrovmState {
    /// VM configuration (vCPU count, memory size, etc.)
    pub vm_config: VmConfigInfo,
}

/// Errors that may occur during snapshot create or restore operations.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// An I/O error occurred while reading or writing snapshot files.
    #[error("snapshot I/O error: {0}")]
    IoError(#[source] std::io::Error),

    /// Failed to serialise the VMM state to JSON.
    #[error("failed to serialize VMM state: {0}")]
    Serialize(#[source] serde_json::Error),

    /// Failed to deserialise the VMM state from JSON.
    #[error("failed to deserialize VMM state: {0}")]
    Deserialize(#[source] serde_json::Error),

    /// The memory snapshot file begins with an unrecognised magic value.
    #[error("invalid snapshot magic; expected DBSNAP01")]
    InvalidMagic,

    /// Guest memory has not been initialized yet.
    #[error("guest memory is not initialized")]
    GuestMemoryNotInitialized,

    /// Could not access a guest memory region.
    #[error("failed to access guest memory region")]
    GuestMemoryAccess,

    /// Failed to pause vCPUs before taking the snapshot.
    #[error("failed to pause vCPUs: {0}")]
    VcpuPause(#[source] VcpuManagerError),

    /// Failed to resume vCPUs after taking the snapshot.
    #[error("failed to resume vCPUs: {0}")]
    VcpuResume(#[source] VcpuManagerError),
}

/// Write the contents of all guest memory regions to `writer`.
///
/// The caller is responsible for opening the destination file; a [`BufWriter`]
/// is recommended to avoid excessive small writes.
pub fn dump_memory<W: Write>(
    vm_as: &GuestAddressSpaceImpl,
    mut writer: W,
) -> Result<(), SnapshotError> {
    let memory = vm_as.memory();

    // Write magic header.
    writer
        .write_all(SNAPSHOT_MAGIC)
        .map_err(SnapshotError::IoError)?;

    // Write number of regions.
    let num_regions = memory.num_regions() as u64;
    writer
        .write_all(&num_regions.to_le_bytes())
        .map_err(SnapshotError::IoError)?;

    // Write each region: [guest_addr: u64][size: u64][data: size bytes].
    for region in memory.iter() {
        let start = region.start_addr().raw_value();
        let size = region.len();

        writer
            .write_all(&start.to_le_bytes())
            .map_err(SnapshotError::IoError)?;
        writer
            .write_all(&size.to_le_bytes())
            .map_err(SnapshotError::IoError)?;

        // Use vm-memory's write_all_to to dump the region contents safely.
        region
            .write_all_to(MemoryRegionAddress(0), &mut writer, size as usize)
            .map_err(|_| SnapshotError::GuestMemoryAccess)?;
    }

    Ok(())
}

/// Restore guest memory from a previously created memory snapshot file using mmap.
///
/// The snapshot file is memory-mapped for efficient access, avoiding large heap
/// allocations. Region headers and data are read from the mapped region and
/// written into the corresponding guest physical address ranges.
pub fn restore_memory(
    vm_as: &GuestAddressSpaceImpl,
    file: &File,
) -> Result<(), SnapshotError> {
    let memory = vm_as.memory();

    let file_size = file
        .metadata()
        .map_err(SnapshotError::IoError)?
        .len() as usize;
    if file_size < 8 {
        return Err(SnapshotError::InvalidMagic);
    }

    // SAFETY: We mmap the file as MAP_PRIVATE | PROT_READ. The file descriptor is
    // valid for the duration of this function, and `file_size` matches the actual
    // file length. The mapping is cleaned up via `munmap` before returning.
    let mmap_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            file_size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if mmap_ptr == libc::MAP_FAILED {
        return Err(SnapshotError::IoError(std::io::Error::last_os_error()));
    }

    // SAFETY: `mmap_ptr` points to a valid mapping of `file_size` bytes created
    // above. The slice is read-only and lives only within this function scope.
    let data = unsafe { std::slice::from_raw_parts(mmap_ptr as *const u8, file_size) };

    // Use a closure so we can always munmap, even on error.
    let result = (|| -> Result<(), SnapshotError> {
        // Verify magic header.
        if &data[..8] != SNAPSHOT_MAGIC {
            return Err(SnapshotError::InvalidMagic);
        }
        let mut offset = 8usize;

        // Read number of regions.
        if data.len() < offset + 8 {
            return Err(SnapshotError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated snapshot file",
            )));
        }
        let num_regions = {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[offset..offset + 8]);
            u64::from_le_bytes(buf) as usize
        };
        offset += 8;

        // Restore each region.
        for _ in 0..num_regions {
            if data.len() < offset + 16 {
                return Err(SnapshotError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated snapshot file",
                )));
            }
            let guest_addr = {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[offset..offset + 8]);
                u64::from_le_bytes(buf)
            };
            offset += 8;
            let size = {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[offset..offset + 8]);
                u64::from_le_bytes(buf) as usize
            };
            offset += 8;

            if data.len() < offset + size {
                return Err(SnapshotError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated snapshot file",
                )));
            }

            memory
                .write_slice(&data[offset..offset + size], GuestAddress(guest_addr))
                .map_err(|_| SnapshotError::GuestMemoryAccess)?;
            offset += size;
        }

        Ok(())
    })();

    // SAFETY: `mmap_ptr` and `file_size` correspond to the mapping created above.
    unsafe {
        libc::munmap(mmap_ptr, file_size);
    }

    result
}

/// Save the serialised `state` as `vmm_state.json` inside `snapshot_dir`.
pub fn save_vmm_state(
    snapshot_dir: &str,
    state: &MicrovmState,
) -> Result<(), SnapshotError> {
    let path = Path::new(snapshot_dir).join(VMM_STATE_FILE);
    let file = File::create(&path).map_err(SnapshotError::IoError)?;
    serde_json::to_writer_pretty(file, state).map_err(SnapshotError::Serialize)
}

/// Load and deserialise the `MicrovmState` from `vmm_state.json` in `snapshot_dir`.
pub fn load_vmm_state(snapshot_dir: &str) -> Result<MicrovmState, SnapshotError> {
    let path = Path::new(snapshot_dir).join(VMM_STATE_FILE);
    let file = File::open(&path).map_err(SnapshotError::IoError)?;
    serde_json::from_reader(file).map_err(SnapshotError::Deserialize)
}

/// Create a snapshot of the VMM configuration and guest memory in `snapshot_dir`.
///
/// `vm_as` is the current guest address space; `vm_config` is the VM configuration
/// to serialise. The caller is responsible for pausing/resuming vCPUs around this
/// call if a consistent memory snapshot is required.
pub fn create_snapshot_files(
    snapshot_dir: &str,
    vm_as: &GuestAddressSpaceImpl,
    vm_config: &VmConfigInfo,
) -> Result<(), SnapshotError> {
    // Ensure the snapshot directory exists.
    fs::create_dir_all(snapshot_dir).map_err(SnapshotError::IoError)?;

    // Serialise VMM state.
    let state = MicrovmState {
        vm_config: vm_config.clone(),
    };
    save_vmm_state(snapshot_dir, &state)?;

    // Dump guest memory.
    let mem_path = Path::new(snapshot_dir).join(MEMORY_FILE);
    let mem_file = File::create(&mem_path).map_err(SnapshotError::IoError)?;
    dump_memory(vm_as, BufWriter::new(mem_file))?;

    Ok(())
}

/// Restore guest memory from a snapshot directory into `vm_as`.
///
/// This function only restores the memory contents; it does not modify the VM
/// configuration. The caller should ensure guest memory has already been
/// initialised to a size compatible with the snapshot.
pub fn restore_snapshot_memory(
    snapshot_dir: &str,
    vm_as: &GuestAddressSpaceImpl,
) -> Result<(), SnapshotError> {
    let mem_path = Path::new(snapshot_dir).join(MEMORY_FILE);
    let mem_file = File::open(&mem_path).map_err(SnapshotError::IoError)?;
    restore_memory(vm_as, &mem_file)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::*;

    fn make_test_memory() -> GuestAddressSpaceImpl {
        use std::sync::Arc;
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("create memory");
        Arc::new(mem)
    }

    #[test]
    fn test_dump_and_restore_memory() {
        let vm_as = make_test_memory();

        // Write a known pattern into the first few bytes.
        {
            let memory = vm_as.memory();
            memory
                .write_slice(&[0xDE, 0xAD, 0xBE, 0xEF], GuestAddress(0))
                .unwrap();
        }

        // Dump to a buffer.
        let mut buf: Vec<u8> = Vec::new();
        dump_memory(&vm_as, &mut buf).expect("dump_memory");

        // Write the buffer to a temporary file for mmap-based restore.
        let dir = std::env::temp_dir().join(format!("dbsnap_dump_restore_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let snap_path = dir.join("memory.bin");
        {
            let mut f = File::create(&snap_path).unwrap();
            f.write_all(&buf).unwrap();
        }

        // Clear the memory region.
        {
            let memory = vm_as.memory();
            memory
                .write_slice(&[0u8; 4], GuestAddress(0))
                .unwrap();
        }

        // Restore from the file using mmap.
        let file = File::open(&snap_path).unwrap();
        restore_memory(&vm_as, &file).expect("restore_memory");

        // Verify the pattern is back.
        let memory = vm_as.memory();
        let mut readback = [0u8; 4];
        memory.read_slice(&mut readback, GuestAddress(0)).unwrap();
        assert_eq!(readback, [0xDE, 0xAD, 0xBE, 0xEF]);

        // Cleanup.
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_restore_invalid_magic() {
        let vm_as = make_test_memory();

        // Write data with wrong magic to a temporary file.
        let dir = std::env::temp_dir().join(format!("dbsnap_bad_magic_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let snap_path = dir.join("memory.bin");
        {
            let mut f = File::create(&snap_path).unwrap();
            f.write_all(b"BADMAGIC\x01\x00\x00\x00\x00\x00\x00\x00")
                .unwrap();
        }

        let file = File::open(&snap_path).unwrap();
        let result = restore_memory(&vm_as, &file);
        assert!(matches!(result, Err(SnapshotError::InvalidMagic)));

        // Cleanup.
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_save_load_vmm_state() {
        let dir = std::env::temp_dir();
        let snapshot_dir = dir.join("dbsnap_test");
        std::fs::create_dir_all(&snapshot_dir).unwrap();
        let snapshot_dir_str = snapshot_dir.to_str().unwrap();

        let state = MicrovmState {
            vm_config: VmConfigInfo::default(),
        };
        save_vmm_state(snapshot_dir_str, &state).expect("save");
        let loaded = load_vmm_state(snapshot_dir_str).expect("load");
        assert_eq!(loaded.vm_config, VmConfigInfo::default());

        // Cleanup
        std::fs::remove_dir_all(&snapshot_dir).ok();
    }
}
