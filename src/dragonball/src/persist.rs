// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// Copyright (C) 2025 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Cursor, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::result::Result;
use std::slice;

use dbs_address_space::{AddressSpace, AddressSpaceRegionType};
use dbs_snapshot::Snapshot;
use dbs_snapshot::SnapshotError;
use log::info;
use vm_memory::GuestAddressSpace;

use crate::api::v1::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::memory_snapshot::{self, SnapshotMemory};
use crate::vcpu::VcpuManagerError;
use crate::vm::persist::{RestoreVmStateError, SaveVmStateError, VmState};
use crate::vm::Vm;

/// Max time for snapshot io drain
pub const MAX_SNAPSHOT_IO_FREEZE_MSEC: u64 = 10000;
/// Max time for live-upgrade io drain
// Since we need to complete the live-upgrade in 200ms
// and the normal save/restore time for vmm is about 40ms,
// we allow 160ms for io drain, beyond which the live-upgrade
// fails and triggers rollback.
pub const MAX_LIVEUPGRADE_IO_FREEZE_MSEC: u64 = 160;

/// Errors associated with Create Snapshot
#[derive(Debug, thiserror::Error)]
pub enum CreateSnapshotError {
    /// Failed to get dirty bitmap.
    #[error("Cannot get dirty bitmap")]
    DirtyBitmap,
    /// Failed to translate microVM version snapshot data version.
    #[error("Cannot translate microVM version to snapshot data version")]
    InvalidVersion,
    /// Failed to write memory to snapshot.
    #[error("Cannot write memory file, {0}")]
    Memory(#[source] memory_snapshot::Error),
    /// Failed to open memory backing file.
    #[error("Cannot open memory file, {0}")]
    MemoryBackingFile(#[source] io::Error),
    /// Failed to save MicrovmState.
    #[error("Cannot save microvm state, {0}")]
    MicrovmState(#[source] SaveVmStateError),
    /// Failed to serialize microVM state.
    #[error("Cannot serialize MicrovmState, {0}")]
    SerializeMicrovmState(SnapshotError),
    /// Failed to open the snapshot backing file.
    #[error("Cannot open snapshot file, {0}")]
    SnapshotBackingFile(#[source] io::Error),
    /// Snapshot again when snapshot is doing.
    #[error("microvm state is not expected")]
    InvalidMicroVmState,
    /// Io Drain failed.
    #[error("io drain failed, {0}")]
    IoDrainFailed(#[source] io::Error),
    /// Invalid Vm Id
    #[error("Invalid Vm Id")]
    InvalidVmId,

    /// Vcpu related error Error
    #[error("Vcpu related error Error, {0}")]
    Vcpu(#[source] VcpuManagerError),
    /// Unlink the memory file failed.
    #[error("Unlink memory file error {0}")]
    UnlinkMemFile(#[source] nix::Error),
    /// Map memory file failed.
    #[error("Map memory file error {0}")]
    MapMemoryFile(#[source] io::Error),
    /// Internal Bugs detected.
    #[error(transparent)]
    Others(#[from] anyhow::Error),
    /// Save debug info failed.
    #[error("Save debug info error {0}")]
    Debug(#[source] io::Error),
    /// TDX 1.0 do not support snapshot
    #[error("TDX do not supported snapshot now")]
    Tdx,
    /// Failpoint error
    #[error("Failpoint error: {0}")]
    Failpoint(String),
    /// Write buffer error
    #[error("Write buffer failed: {0}")]
    WriteBuffer(String),
    /// Snapshot not supported
    #[error("Snapshot not supported")]
    SnapshotNotSupported,
    /// Reset Io Drainer failed
    #[error("Reset Io Drainer failed: {0:?}")]
    ResetIoDrainer(#[source] io::Error),
}

/// Errors associated with loading a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum LoadSnapshotError {
    /// Failed to deserialize microVM state.
    #[error("Cannot deserialize MicrovmState, {0}")]
    DeserializeMicrovmState(#[source] SnapshotError),
    /// Failed to open memory backing file.
    #[error("Cannot open memory file, {0}")]
    MemoryBackingFile(#[source] io::Error),
    /// Failed to open the snapshot backing file.
    #[error("Cannot open snapshot file, {0}")]
    SnapshotBackingFile(#[source] io::Error),
    /// Failed to restore microVm state.
    #[error("Failed to restore microVm state, {0}")]
    RestoreVmState(#[source] RestoreVmStateError),
    /// Vm already Run
    #[error("MicroVm already running")]
    AlreadyRunning,
    /// Invalid Vm Id
    #[error(" Invalid Vm Id")]
    InvalidVmId,
    /// Snapshot not supported
    #[error("Snapshot not supported")]
    SnapshotNotSupported,
    /// Failpoint error
    #[error("Failpoint error: {0}")]
    Failpoint(String),
    /// Internal Bugs detected.
    #[error(transparent)]
    Others(#[from] anyhow::Error),
}

// We calculate the memory file size by address_space, because address_space
// has region type information and knows which region is reserved and which is
// not. For example, in the Function Compute with virtiofs enable DAX scenarios,
// if vm_as is used to calculate the memory size, a large value is obtained.
// Like: the memory is only 128 MB, but the DAX is 1 GB, so a 1.1GB memory file
// will be generated when the template is generated. Using this function solves
// this problem because DAX is DAXMemory and will be filtered out.
//
// Same to DeviceMemory.
fn mem_size_byte(address_space: &AddressSpace) -> u64 {
    let mut length = 0;

    // It's safe to unwrap since it never return Err in closure
    address_space
        .walk_regions(|region| {
            if region.region_type() != AddressSpaceRegionType::DAXMemory
                && region.region_type() != AddressSpaceRegionType::DeviceMemory
            {
                length += region.len();
            }
            Ok(())
        })
        .unwrap();
    length
}

fn snapshot_memory_to_file(
    vm: &Vm,
    mem_file_path: &Path,
    snapshot_type: &SnapshotType,
) -> Result<(), CreateSnapshotError> {
    // it's safe to unwrap since it doesn't make sense to snapshot a microVM
    // that has not been started.
    let mem_size_byte = mem_size_byte(vm.vm_address_space().unwrap());

    let file_path = Path::new(mem_file_path);
    if file_path.exists() {
        nix::unistd::unlink(mem_file_path).map_err(CreateSnapshotError::UnlinkMemFile)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(mem_file_path)
        .map_err(CreateSnapshotError::MemoryBackingFile)?;

    file.set_len(mem_size_byte)
        .map_err(CreateSnapshotError::MemoryBackingFile)?;

    match snapshot_type {
        SnapshotType::Diff => {
            let dirty_bitmap = vm
                .get_dirty_bitmap()
                .map_err(|_| CreateSnapshotError::DirtyBitmap)?;
            vm.vm_as()
                .unwrap()
                .memory()
                .dump_dirty(&mut file, &dirty_bitmap)
                .map_err(CreateSnapshotError::Memory)
        }
        SnapshotType::Full => {
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mem_size_byte as usize,
                    libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if addr == libc::MAP_FAILED {
                return Err(CreateSnapshotError::MapMemoryFile(
                    std::io::Error::last_os_error(),
                ));
            }
            let mem_slice: &mut [u8] =
                unsafe { slice::from_raw_parts_mut(addr as *mut u8, mem_size_byte as usize) };
            let mut cursor = Cursor::new(mem_slice);

            vm.vm_as()
                .unwrap()
                .memory()
                .dump(&mut cursor, vm.vm_address_space())
                .map_err(CreateSnapshotError::Memory)
        }
    }
}

fn snapshot_memory_from_file(
    mem_file_path: &Path,
    is_gshmem: bool,
) -> Result<File, LoadSnapshotError> {
    OpenOptions::new()
        .read(true)
        .write(is_gshmem)
        .open(mem_file_path)
        .map_err(LoadSnapshotError::MemoryBackingFile)
}

fn snapshot_state_to_file(
    microvm_state: &VmState,
    snapshot_path: &Path,
    _version: &Option<String>,
    debug_path: Option<String>,
) -> Result<(), CreateSnapshotError> {
    let mut snapshot_file = std::io::BufWriter::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(snapshot_path)
            .map_err(CreateSnapshotError::SnapshotBackingFile)?,
    );

    snapshot_state_to_buff(microvm_state, &mut snapshot_file, _version, debug_path)?;
    Ok(())
}

fn snapshot_state_to_buff(
    microvm_state: &VmState,
    writer: &mut impl io::Write,
    _version: &Option<String>,
    debug_path: Option<String>,
) -> Result<(), CreateSnapshotError> {
    if let Some(suffix) = debug_path {
        let str_vm_state = format!("{:#?}", microvm_state);
        let save_path = format!("/tmp/vmstate-save-{}.txt", suffix);
        let mut file = File::create(save_path).map_err(CreateSnapshotError::Debug)?;
        file.write_all(str_vm_state.as_bytes())
            .map_err(CreateSnapshotError::Debug)?;
    }

    use self::CreateSnapshotError::SerializeMicrovmState;
    let snapshot = Snapshot::new(microvm_state);
    snapshot.save(writer).map_err(SerializeMicrovmState)?;

    Ok(())
}

pub fn snapshot_state_from_file(
    snapshot_path: &Path,
) -> Result<VmState, LoadSnapshotError> {
    let mut snapshot_reader = std::io::BufReader::new(
        File::open(snapshot_path).map_err(LoadSnapshotError::SnapshotBackingFile)?,
    );
    let snapshot: Snapshot<VmState> = Snapshot::load(&mut snapshot_reader)
        .map_err(LoadSnapshotError::DeserializeMicrovmState)?;

    Ok(snapshot.data)
}

/// Creates a Microvm snapshot.
pub fn create_vm_snapshot(
    vm: &Vm,
    params: &CreateSnapshotParams,
) -> Result<(), CreateSnapshotError> {
    snapshot_memory_to_file(vm, &params.mem_file_path, &params.snapshot_type)?;
    info!("[snapshot] memory file created");

    let vm_state = vm.save_state().map_err(CreateSnapshotError::MicrovmState)?;

    let mut debug_path = None;
    if params.debug.unwrap_or(false) {
        let instance_id = vm.shared_info().read().unwrap().id.clone();
        debug_path = Some(format!("snapshot-{}", instance_id));
    }

    snapshot_state_to_file(&vm_state, &params.snapshot_path, &params.version, debug_path)?;

    info!("[snapshot] state file created");
    Ok(())
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn load_vm_snapshot(
    params: &LoadSnapshotParams,
) -> Result<(VmState, File, bool, bool), LoadSnapshotError> {
    let track_dirty = params.enable_diff_snapshots;
    let is_gshmem = params.is_gshmem;

    let vm_state = snapshot_state_from_file(&params.snapshot_path)?;
    let memory_file = snapshot_memory_from_file(&params.mem_file_path, is_gshmem)?;

    info!("[snapshot] snapshot file loaded");
    Ok((vm_state, memory_file, is_gshmem, track_dirty))
}

/// Creates a Microvm snapshot for live-upgrade.
pub fn create_vm_live_upgrade_state(
    vm: &mut Vm,
    debug_path: Option<String>,
) -> Result<Vec<u8>, CreateSnapshotError> {
    let vm_state = vm
        .live_upgrade_save_state()
        .map_err(CreateSnapshotError::MicrovmState)?;
    log::debug!("live upgrade live_upgrade_save_state end.");

    let mut snapshot_buf_writer = std::io::BufWriter::new(Vec::<u8>::new());
    snapshot_state_to_buff(&vm_state, &mut snapshot_buf_writer, &None, debug_path)?;

    info!("live upgrade state buffer created");

    let buf = snapshot_buf_writer
        .into_inner()
        .map_err(|e| CreateSnapshotError::WriteBuffer(e.to_string()))?;

    Ok(buf)
}

pub fn load_vm_live_upgrade_state(
    state_buf: &mut Vec<u8>,
) -> Result<VmState, LoadSnapshotError> {
    info!("liveupgrade: load state start");
    let snapshot: Snapshot<VmState> = Snapshot::load(&mut state_buf.as_slice())
        .map_err(LoadSnapshotError::DeserializeMicrovmState)?;
    info!("liveupgrade: load state end");
    Ok(snapshot.data)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use dbs_address_space::{AddressSpace, AddressSpaceLayout, AddressSpaceRegion, AddressSpaceRegionType};
    use vm_memory::GuestAddress;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::test_utils::tests::create_vm_for_test;
    use test_utils::skip_if_not_root;

    const GUEST_PHYS_END: u64 = (1 << 46) - 1;
    const GUEST_MEM_END: u64 = GUEST_PHYS_END >> 1;
    const GUEST_DEVICE_START: u64 = GUEST_MEM_END + 1;

    fn create_address_space_layout() -> AddressSpaceLayout {
        AddressSpaceLayout::new(GUEST_PHYS_END, 0, GUEST_DEVICE_START)
    }

    #[test]
    fn test_persist_snapshot_state() {
        skip_if_not_root!();
        let vm = create_vm_for_test();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        vm.create_pit().unwrap();

        let vm_state = vm.save_state().unwrap();
        let snapshot_path = TempFile::new().unwrap();
        let snapshot_path_buf = PathBuf::from(snapshot_path.as_path());

        // test normal case
        assert!(snapshot_state_to_file(
            &vm_state,
            &PathBuf::from(snapshot_path.as_path()),
            &None,
            None,
        )
        .is_ok());

        // test restore state from file
        match snapshot_state_from_file(&snapshot_path_buf) {
            Ok(restored_vm_state) => assert!(vm_state == restored_vm_state),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn test_persist_snapshot_memory() {
        skip_if_not_root!();
        let vm = create_vm_for_test();

        let mem_file_path = TempFile::new().unwrap();
        let mem_file_path_buf = PathBuf::from(mem_file_path.as_path());
        // test snapshot full memory to file
        assert!(snapshot_memory_to_file(&vm, &mem_file_path_buf, &SnapshotType::Full).is_ok());
        // test snapshot memory from file
        assert!(snapshot_memory_from_file(&mem_file_path_buf, false).is_ok());
    }

    #[test]
    fn test_mem_size_byte() {
        let reg1 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
        );
        let reg2 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x2000),
            0x1000,
        );
        let reg3 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DAXMemory,
            GuestAddress(GUEST_DEVICE_START),
            0x1000,
        );
        let regions = vec![Arc::new(reg1), Arc::new(reg2), Arc::new(reg3)];
        let layout = create_address_space_layout();
        let address_space = AddressSpace::from_regions(regions, layout);
        let size = mem_size_byte(&address_space);
        assert_eq!(size, 0x2000);
    }
}
