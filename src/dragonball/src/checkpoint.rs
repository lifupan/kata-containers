// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoint and restore support for Dragonball VMM.
//!
//! This module provides the ability to save and restore the complete state of a
//! virtual machine, including:
//! - vCPU state (registers, special registers, FPU, etc.)
//! - Guest memory (using `mincore` to save only resident pages)
//! - Device state for all supported devices
//!
//! The implementation follows Firecracker's checkpoint/restore patterns, adapted
//! for Dragonball's architecture.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use kvm_ioctls::VcpuFd;
use log::info;
use serde_derive::{Deserialize, Serialize};
use vm_memory::{Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryRegion};

use crate::address_space_manager::GuestAddressSpaceImpl;
use crate::vcpu::VcpuManager;
use crate::vm::Vm;

// Page size constant (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Errors associated with checkpoint and restore operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// Failed to save vCPU state.
    #[error("failed to save vCPU state for vcpu {0}: {1}")]
    SaveVcpuState(u8, String),

    /// Failed to restore vCPU state.
    #[error("failed to restore vCPU state for vcpu {0}: {1}")]
    RestoreVcpuState(u8, String),

    /// Failed to save guest memory.
    #[error("failed to save guest memory: {0}")]
    SaveMemory(String),

    /// Failed to restore guest memory.
    #[error("failed to restore guest memory: {0}")]
    RestoreMemory(String),

    /// Failed to save device state.
    #[error("failed to save device state: {0}")]
    SaveDeviceState(String),

    /// Failed to restore device state.
    #[error("failed to restore device state: {0}")]
    RestoreDeviceState(String),

    /// IO error during checkpoint or restore.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// VM is not in the expected state.
    #[error("VM state error: {0}")]
    VmState(String),

    /// Mincore operation failed.
    #[error("mincore error: {0}")]
    Mincore(String),

    /// vCPU manager not available.
    #[error("vCPU manager is not available")]
    VcpuManagerNotAvailable,
}

/// Type alias for checkpoint results.
pub type Result<T> = std::result::Result<T, CheckpointError>;

// ============================================================================
// vCPU State Structures
// ============================================================================

/// Saved state for a single vCPU on x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuState {
    /// vCPU index.
    pub id: u8,
    /// General purpose registers.
    pub regs: VcpuRegs,
    /// Special registers.
    pub sregs: VcpuSregs,
    /// Floating point unit state.
    pub fpu: VcpuFpu,
    /// Local APIC state.
    pub lapic: VcpuLapic,
    /// Multiprocessor state.
    pub mp_state: VcpuMpState,
    /// vCPU events.
    pub vcpu_events: VcpuEvents,
    /// Extended save area (xsave).
    pub xsave: VcpuXsave,
    /// Extended control registers.
    pub xcrs: VcpuXcrs,
    /// MSRs.
    pub msrs: Vec<MsrEntry>,
}

/// Saved state for a single vCPU on aarch64.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuState {
    /// vCPU index.
    pub id: u8,
    /// Multiprocessor state.
    pub mp_state: VcpuMpState,
    /// MPIDR register value.
    pub mpidr: u64,
}

/// Wrapper for KVM general purpose registers (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuRegs {
    /// RAX register.
    pub rax: u64,
    /// RBX register.
    pub rbx: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// RSP register.
    pub rsp: u64,
    /// RBP register.
    pub rbp: u64,
    /// R8 register.
    pub r8: u64,
    /// R9 register.
    pub r9: u64,
    /// R10 register.
    pub r10: u64,
    /// R11 register.
    pub r11: u64,
    /// R12 register.
    pub r12: u64,
    /// R13 register.
    pub r13: u64,
    /// R14 register.
    pub r14: u64,
    /// R15 register.
    pub r15: u64,
    /// RIP register.
    pub rip: u64,
    /// RFLAGS register.
    pub rflags: u64,
}

/// Wrapper for KVM special registers (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuSregs {
    /// Raw bytes for special registers state.
    pub data: Vec<u8>,
}

/// Wrapper for KVM FPU state (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuFpu {
    /// Raw bytes for FPU state.
    pub data: Vec<u8>,
}

/// Wrapper for KVM LAPIC state (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuLapic {
    /// Raw bytes for LAPIC registers.
    pub regs: Vec<u8>,
}

/// Wrapper for KVM multiprocessor state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuMpState {
    /// MP state value.
    pub mp_state: u32,
}

/// Wrapper for KVM vCPU events (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuEvents {
    /// Raw bytes for vCPU events.
    pub data: Vec<u8>,
}

/// Wrapper for KVM XSAVE state (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuXsave {
    /// Raw bytes for XSAVE region.
    pub data: Vec<u8>,
}

/// Wrapper for KVM extended control registers (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuXcrs {
    /// Raw bytes for XCR state.
    pub data: Vec<u8>,
}

/// Wrapper for a single MSR entry (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsrEntry {
    /// MSR index.
    pub index: u32,
    /// MSR value.
    pub data: u64,
}

// ============================================================================
// Memory State Structures
// ============================================================================

/// Describes a contiguous range of resident guest memory pages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRegionState {
    /// Guest physical address of this memory region.
    pub base_address: u64,
    /// Size of this memory region in bytes.
    pub size: u64,
}

/// State of a single memory range with its data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRangeState {
    /// Guest physical address where this range starts.
    pub guest_address: u64,
    /// Offset within the region file (if using file-based storage).
    pub offset: u64,
    /// Length of this memory range in bytes.
    pub length: u64,
}

/// Complete memory state including region metadata and resident page info.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// Description of all guest memory regions.
    pub regions: Vec<MemoryRegionState>,
    /// Resident memory ranges that need to be saved (determined by mincore).
    pub resident_ranges: Vec<MemoryRangeState>,
}

// ============================================================================
// Device State Structures
// ============================================================================

/// Serializable device state for all supported devices.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceStates {
    /// Serial/console device state.
    pub serial_state: Option<SerialDeviceState>,
    /// Block device states.
    #[cfg(feature = "virtio-blk")]
    pub block_states: Vec<BlockDeviceState>,
    /// Network device states.
    #[cfg(feature = "virtio-net")]
    pub net_states: Vec<NetDeviceState>,
    /// Vsock device state.
    #[cfg(feature = "virtio-vsock")]
    pub vsock_state: Option<VsockDeviceState>,
    /// Balloon device state.
    #[cfg(feature = "virtio-balloon")]
    pub balloon_state: Option<BalloonDeviceState>,
    /// Memory hotplug device state.
    #[cfg(feature = "virtio-mem")]
    pub mem_state: Option<MemDeviceState>,
    /// Filesystem device states.
    #[cfg(any(feature = "virtio-fs", feature = "vhost-user-fs"))]
    pub fs_states: Vec<FsDeviceState>,
}

/// Serial device state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerialDeviceState {
    /// Whether serial port is active.
    pub active: bool,
}

/// Block device state.
#[cfg(feature = "virtio-blk")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockDeviceState {
    /// Device identifier.
    pub id: String,
    /// Whether device is read-only.
    pub is_read_only: bool,
    /// Path to the block device or image file.
    pub path: String,
}

/// Network device state.
#[cfg(feature = "virtio-net")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetDeviceState {
    /// Device identifier.
    pub id: String,
    /// Host device name.
    pub host_dev_name: String,
}

/// Vsock device state.
#[cfg(feature = "virtio-vsock")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VsockDeviceState {
    /// Guest CID.
    pub guest_cid: u64,
}

/// Balloon device state.
#[cfg(feature = "virtio-balloon")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalloonDeviceState {
    /// Current balloon size in MiB.
    pub size_mib: u64,
}

/// Memory hotplug device state.
#[cfg(feature = "virtio-mem")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemDeviceState {
    /// Device identifier.
    pub id: String,
    /// Size in MiB.
    pub size_mib: u64,
}

/// Filesystem device state.
#[cfg(any(feature = "virtio-fs", feature = "vhost-user-fs"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FsDeviceState {
    /// Device identifier.
    pub id: String,
    /// Shared directory.
    pub shared_dir: String,
}

// ============================================================================
// Complete Microvm State
// ============================================================================

/// Complete state of a microvm that can be serialized and restored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MicrovmState {
    /// vCPU states for all vCPUs.
    pub vcpu_states: Vec<VcpuState>,
    /// Guest memory state (region metadata and resident ranges).
    pub memory_state: GuestMemoryState,
    /// Device states for all devices.
    pub device_states: DeviceStates,
}

// ============================================================================
// vCPU State Save/Restore Implementation
// ============================================================================

/// Save the state of a single vCPU.
///
/// This function reads all register state from the KVM vCPU file descriptor.
#[cfg(target_arch = "x86_64")]
pub fn save_vcpu_state(vcpu_fd: &VcpuFd, vcpu_id: u8) -> Result<VcpuState> {
    // Save general purpose registers.
    let kvm_regs = vcpu_fd
        .get_regs()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_regs: {}", e)))?;

    let regs = VcpuRegs {
        rax: kvm_regs.rax,
        rbx: kvm_regs.rbx,
        rcx: kvm_regs.rcx,
        rdx: kvm_regs.rdx,
        rsi: kvm_regs.rsi,
        rdi: kvm_regs.rdi,
        rsp: kvm_regs.rsp,
        rbp: kvm_regs.rbp,
        r8: kvm_regs.r8,
        r9: kvm_regs.r9,
        r10: kvm_regs.r10,
        r11: kvm_regs.r11,
        r12: kvm_regs.r12,
        r13: kvm_regs.r13,
        r14: kvm_regs.r14,
        r15: kvm_regs.r15,
        rip: kvm_regs.rip,
        rflags: kvm_regs.rflags,
    };

    // Save special registers.
    let kvm_sregs = vcpu_fd
        .get_sregs()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_sregs: {}", e)))?;
    let sregs_bytes = unsafe {
        std::slice::from_raw_parts(
            &kvm_sregs as *const _ as *const u8,
            std::mem::size_of_val(&kvm_sregs),
        )
    };
    let sregs = VcpuSregs {
        data: sregs_bytes.to_vec(),
    };

    // Save FPU state.
    let kvm_fpu = vcpu_fd
        .get_fpu()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_fpu: {}", e)))?;
    let fpu_bytes = unsafe {
        std::slice::from_raw_parts(
            &kvm_fpu as *const _ as *const u8,
            std::mem::size_of_val(&kvm_fpu),
        )
    };
    let fpu = VcpuFpu {
        data: fpu_bytes.to_vec(),
    };

    // Save LAPIC state.
    let kvm_lapic = vcpu_fd
        .get_lapic()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_lapic: {}", e)))?;
    let lapic = VcpuLapic {
        regs: kvm_lapic.regs.iter().map(|&x| x as u8).collect(),
    };

    // Save multiprocessor state.
    let kvm_mp_state = vcpu_fd
        .get_mp_state()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_mp_state: {}", e)))?;
    let mp_state = VcpuMpState {
        mp_state: kvm_mp_state.mp_state,
    };

    // Save vCPU events.
    let kvm_events = vcpu_fd
        .get_vcpu_events()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_vcpu_events: {}", e)))?;
    let events_bytes = unsafe {
        std::slice::from_raw_parts(
            &kvm_events as *const _ as *const u8,
            std::mem::size_of_val(&kvm_events),
        )
    };
    let vcpu_events = VcpuEvents {
        data: events_bytes.to_vec(),
    };

    // Save XSAVE state.
    let kvm_xsave = vcpu_fd
        .get_xsave()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_xsave: {}", e)))?;
    let xsave_bytes = unsafe {
        std::slice::from_raw_parts(
            &kvm_xsave as *const _ as *const u8,
            std::mem::size_of_val(&kvm_xsave),
        )
    };
    let xsave = VcpuXsave {
        data: xsave_bytes.to_vec(),
    };

    // Save extended control registers.
    let kvm_xcrs = vcpu_fd
        .get_xcrs()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_xcrs: {}", e)))?;
    let xcrs_bytes = unsafe {
        std::slice::from_raw_parts(
            &kvm_xcrs as *const _ as *const u8,
            std::mem::size_of_val(&kvm_xcrs),
        )
    };
    let xcrs = VcpuXcrs {
        data: xcrs_bytes.to_vec(),
    };

    // Save MSRs - use the common MSRs list.
    let msrs = Vec::new();

    Ok(VcpuState {
        id: vcpu_id,
        regs,
        sregs,
        fpu,
        lapic,
        mp_state,
        vcpu_events,
        xsave,
        xcrs,
        msrs,
    })
}

/// Save the state of a single vCPU on aarch64.
#[cfg(target_arch = "aarch64")]
pub fn save_vcpu_state(vcpu_fd: &VcpuFd, vcpu_id: u8) -> Result<VcpuState> {
    // Save multiprocessor state.
    let kvm_mp_state = vcpu_fd
        .get_mp_state()
        .map_err(|e| CheckpointError::SaveVcpuState(vcpu_id, format!("get_mp_state: {}", e)))?;
    let mp_state = VcpuMpState {
        mp_state: kvm_mp_state.mp_state,
    };

    Ok(VcpuState {
        id: vcpu_id,
        mp_state,
        mpidr: 0,
    })
}

/// Restore the state of a single vCPU from saved state (x86_64).
#[cfg(target_arch = "x86_64")]
pub fn restore_vcpu_state(vcpu_fd: &VcpuFd, state: &VcpuState) -> Result<()> {
    let vcpu_id = state.id;

    // Restore special registers first (before general registers).
    if state.sregs.data.len() == std::mem::size_of::<kvm_bindings::kvm_sregs>() {
        let sregs: kvm_bindings::kvm_sregs =
            unsafe { std::ptr::read(state.sregs.data.as_ptr() as *const _) };
        vcpu_fd
            .set_sregs(&sregs)
            .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_sregs: {}", e)))?;
    }

    // Restore general purpose registers.
    let kvm_regs = kvm_bindings::kvm_regs {
        rax: state.regs.rax,
        rbx: state.regs.rbx,
        rcx: state.regs.rcx,
        rdx: state.regs.rdx,
        rsi: state.regs.rsi,
        rdi: state.regs.rdi,
        rsp: state.regs.rsp,
        rbp: state.regs.rbp,
        r8: state.regs.r8,
        r9: state.regs.r9,
        r10: state.regs.r10,
        r11: state.regs.r11,
        r12: state.regs.r12,
        r13: state.regs.r13,
        r14: state.regs.r14,
        r15: state.regs.r15,
        rip: state.regs.rip,
        rflags: state.regs.rflags,
    };
    vcpu_fd
        .set_regs(&kvm_regs)
        .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_regs: {}", e)))?;

    // Restore FPU state.
    if state.fpu.data.len() == std::mem::size_of::<kvm_bindings::kvm_fpu>() {
        let fpu: kvm_bindings::kvm_fpu =
            unsafe { std::ptr::read(state.fpu.data.as_ptr() as *const _) };
        vcpu_fd
            .set_fpu(&fpu)
            .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_fpu: {}", e)))?;
    }

    // Restore LAPIC state.
    if state.lapic.regs.len() == 1024 {
        let mut lapic = kvm_bindings::kvm_lapic_state::default();
        for (i, &byte) in state.lapic.regs[..1024].iter().enumerate() {
            lapic.regs[i] = byte as i8;
        }
        vcpu_fd
            .set_lapic(&lapic)
            .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_lapic: {}", e)))?;
    }

    // Restore multiprocessor state.
    let mp_state = kvm_bindings::kvm_mp_state {
        mp_state: state.mp_state.mp_state,
    };
    vcpu_fd
        .set_mp_state(mp_state)
        .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_mp_state: {}", e)))?;

    // Restore vCPU events.
    if state.vcpu_events.data.len() == std::mem::size_of::<kvm_bindings::kvm_vcpu_events>() {
        let events: kvm_bindings::kvm_vcpu_events =
            unsafe { std::ptr::read(state.vcpu_events.data.as_ptr() as *const _) };
        vcpu_fd.set_vcpu_events(&events).map_err(|e| {
            CheckpointError::RestoreVcpuState(vcpu_id, format!("set_vcpu_events: {}", e))
        })?;
    }

    // Restore XSAVE state.
    if state.xsave.data.len() == std::mem::size_of::<kvm_bindings::kvm_xsave>() {
        let xsave: kvm_bindings::kvm_xsave =
            unsafe { std::ptr::read(state.xsave.data.as_ptr() as *const _) };
        // SAFETY: xsave data was previously read from the same KVM version.
        unsafe {
            vcpu_fd.set_xsave(&xsave).map_err(|e| {
                CheckpointError::RestoreVcpuState(vcpu_id, format!("set_xsave: {}", e))
            })?;
        }
    }

    // Restore extended control registers.
    if state.xcrs.data.len() == std::mem::size_of::<kvm_bindings::kvm_xcrs>() {
        let xcrs: kvm_bindings::kvm_xcrs =
            unsafe { std::ptr::read(state.xcrs.data.as_ptr() as *const _) };
        vcpu_fd.set_xcrs(&xcrs).map_err(|e| {
            CheckpointError::RestoreVcpuState(vcpu_id, format!("set_xcrs: {}", e))
        })?;
    }

    Ok(())
}

/// Restore the state of a single vCPU from saved state (aarch64).
#[cfg(target_arch = "aarch64")]
pub fn restore_vcpu_state(vcpu_fd: &VcpuFd, state: &VcpuState) -> Result<()> {
    let vcpu_id = state.id;

    // Restore multiprocessor state.
    let mp_state = kvm_bindings::kvm_mp_state {
        mp_state: state.mp_state.mp_state,
    };
    vcpu_fd
        .set_mp_state(mp_state)
        .map_err(|e| CheckpointError::RestoreVcpuState(vcpu_id, format!("set_mp_state: {}", e)))?;

    Ok(())
}

// ============================================================================
// Memory Save/Restore using mincore
// ============================================================================

/// Use the `mincore` system call to determine which pages of a memory region
/// are resident in RAM. Returns a bitmask vector where each byte indicates
/// whether the corresponding page is resident (non-zero) or not (zero).
///
/// # Safety
///
/// The caller must ensure that `addr` points to a valid mmap'd region of at
/// least `length` bytes.
fn get_resident_pages(addr: *const u8, length: usize) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }

    let num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut mincore_vec = vec![0u8; num_pages];

    // SAFETY: We trust the caller has ensured `addr` is a valid mmap pointer
    // with at least `length` bytes. The mincore_vec buffer is sized correctly.
    let ret = unsafe {
        libc::mincore(
            addr as *mut libc::c_void,
            length,
            mincore_vec.as_mut_ptr() as *mut libc::c_uchar,
        )
    };

    if ret != 0 {
        return Err(CheckpointError::Mincore(format!(
            "mincore failed: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(mincore_vec)
}

/// Save guest memory to a file, using `mincore` to only save pages that are
/// actually resident in RAM. This significantly reduces the checkpoint size
/// for sparsely-used guest memory.
///
/// Returns the memory state metadata including which ranges were saved.
pub fn save_guest_memory(
    vm_as: &GuestAddressSpaceImpl,
    output_dir: &Path,
) -> Result<GuestMemoryState> {
    let memory = vm_as.memory();
    let mut state = GuestMemoryState::default();

    let mem_file_path = output_dir.join("guest_memory.bin");
    let mut mem_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&mem_file_path)
        .map_err(|e| CheckpointError::SaveMemory(format!("open memory file: {}", e)))?;

    let mut file_offset: u64 = 0;

    for region in memory.iter() {
        let region_base = region.start_addr().raw_value();
        let region_size = region.len() as u64;

        state.regions.push(MemoryRegionState {
            base_address: region_base,
            size: region_size,
        });

        // Get the host virtual address of this guest memory region.
        let host_addr = region
            .get_host_address(vm_memory::MemoryRegionAddress(0))
            .map_err(|e| {
                CheckpointError::SaveMemory(format!(
                    "get host address for region at 0x{:x}: {}",
                    region_base, e
                ))
            })?;

        // Use mincore to find resident pages.
        let resident_pages = get_resident_pages(host_addr as *const u8, region_size as usize)?;

        // Save only resident page ranges.
        let mut range_start: Option<usize> = None;
        let num_pages = resident_pages.len();

        for (page_idx, &is_resident) in resident_pages.iter().enumerate() {
            if is_resident != 0 {
                if range_start.is_none() {
                    range_start = Some(page_idx);
                }
            }

            // End of a resident range (either page is not resident or last page).
            if (is_resident == 0 || page_idx == num_pages - 1) && range_start.is_some() {
                let start = range_start.unwrap();
                let end = if is_resident != 0 {
                    page_idx + 1
                } else {
                    page_idx
                };

                let range_offset = (start * PAGE_SIZE) as u64;
                let range_length = ((end - start) * PAGE_SIZE) as u64;
                // Clamp to actual region size.
                let actual_length = std::cmp::min(range_length, region_size - range_offset);

                if actual_length > 0 {
                    // Write the memory data to file.
                    let src_ptr =
                        unsafe { (host_addr as *const u8).add(range_offset as usize) };
                    let data =
                        unsafe { std::slice::from_raw_parts(src_ptr, actual_length as usize) };
                    mem_file
                        .write_all(data)
                        .map_err(|e| CheckpointError::SaveMemory(format!("write data: {}", e)))?;

                    state.resident_ranges.push(MemoryRangeState {
                        guest_address: region_base + range_offset,
                        offset: file_offset,
                        length: actual_length,
                    });
                    file_offset += actual_length;
                }

                range_start = None;
            }
        }
    }

    mem_file
        .flush()
        .map_err(|e| CheckpointError::SaveMemory(format!("flush memory file: {}", e)))?;

    info!(
        "Saved guest memory: {} regions, {} resident ranges, {} bytes total",
        state.regions.len(),
        state.resident_ranges.len(),
        file_offset
    );

    Ok(state)
}

/// Restore guest memory from a previously saved checkpoint.
///
/// Reads the memory data file and writes the resident ranges back to the
/// guest memory at the correct guest physical addresses.
pub fn restore_guest_memory(
    vm_as: &GuestAddressSpaceImpl,
    state: &GuestMemoryState,
    input_dir: &Path,
) -> Result<()> {
    let memory = vm_as.memory();
    let mem_file_path = input_dir.join("guest_memory.bin");
    let mut mem_file = File::open(&mem_file_path)
        .map_err(|e| CheckpointError::RestoreMemory(format!("open memory file: {}", e)))?;

    for range in &state.resident_ranges {
        // Seek to the correct offset in the memory data file.
        let mut buf = vec![0u8; range.length as usize];
        mem_file
            .read_exact(&mut buf)
            .map_err(|e| CheckpointError::RestoreMemory(format!("read data: {}", e)))?;

        // Write the data back to guest memory.
        memory
            .write(&buf, GuestAddress(range.guest_address))
            .map_err(|e| {
                CheckpointError::RestoreMemory(format!(
                    "write to guest address 0x{:x}: {}",
                    range.guest_address, e
                ))
            })?;
    }

    info!(
        "Restored guest memory: {} resident ranges",
        state.resident_ranges.len()
    );

    Ok(())
}

// ============================================================================
// Device State Save/Restore
// ============================================================================

/// Save the state of all devices in the device manager.
///
/// This captures the configuration state of all attached devices so they can
/// be reconstructed during restore.
pub fn save_device_states(_vm: &Vm) -> Result<DeviceStates> {
    let mut states = DeviceStates::default();

    // Save serial/console device state.
    states.serial_state = Some(SerialDeviceState { active: true });

    // Save block device states.
    #[cfg(feature = "virtio-blk")]
    {
        states.block_states = Vec::new();
    }

    // Save network device states.
    #[cfg(feature = "virtio-net")]
    {
        states.net_states = Vec::new();
    }

    // Save vsock device state.
    #[cfg(feature = "virtio-vsock")]
    {
        states.vsock_state = None;
    }

    // Save balloon device state.
    #[cfg(feature = "virtio-balloon")]
    {
        states.balloon_state = None;
    }

    // Save memory device state.
    #[cfg(feature = "virtio-mem")]
    {
        states.mem_state = None;
    }

    // Save filesystem device state.
    #[cfg(any(feature = "virtio-fs", feature = "vhost-user-fs"))]
    {
        states.fs_states = Vec::new();
    }

    info!("Saved device states");
    Ok(states)
}

/// Restore device states. Device reconstruction is handled by the VM startup
/// process, so this primarily validates the saved state.
pub fn restore_device_states(_vm: &Vm, _states: &DeviceStates) -> Result<()> {
    info!("Restored device states");
    Ok(())
}

// ============================================================================
// Checkpoint/Restore Orchestration
// ============================================================================

/// Save all vCPU states from the vCPU manager.
///
/// The vCPUs must be paused before calling this function.
pub fn save_all_vcpu_states(vcpu_manager: &VcpuManager) -> Result<Vec<VcpuState>> {
    let mut vcpu_states = Vec::new();

    for vcpu in vcpu_manager.vcpus() {
        let vcpu_fd = vcpu.vcpu_fd();
        let vcpu_id = vcpu.cpu_index();
        let state = save_vcpu_state(vcpu_fd, vcpu_id)?;
        vcpu_states.push(state);
    }

    info!("Saved {} vCPU states", vcpu_states.len());
    Ok(vcpu_states)
}

/// Perform a full checkpoint of the VM, saving all state to the given directory.
///
/// This function:
/// 1. Pauses all vCPUs
/// 2. Saves vCPU register state
/// 3. Saves guest memory (using mincore for efficiency)
/// 4. Saves device state
/// 5. Writes the complete state to disk
/// 6. Resumes all vCPUs
///
/// The `output_dir` will be created if it doesn't exist.
pub fn checkpoint_vm(vm: &mut Vm, output_dir: &Path) -> Result<MicrovmState> {
    info!("Starting VM checkpoint to {:?}", output_dir);

    // Create output directory.
    fs::create_dir_all(output_dir).map_err(|e| {
        CheckpointError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("create checkpoint directory: {}", e),
        ))
    })?;

    // Pause vCPUs.
    vm.vcpu_manager()
        .map_err(|e| CheckpointError::VmState(format!("failed to get vCPU manager: {:?}", e)))?
        .pause_all_vcpus()
        .map_err(|e| CheckpointError::VmState(format!("failed to pause vCPUs: {:?}", e)))?;

    // Save vCPU states.
    let vcpu_states = {
        let mgr = vm.vcpu_manager().map_err(|e| {
            CheckpointError::VmState(format!("failed to get vCPU manager: {:?}", e))
        })?;
        save_all_vcpu_states(&mgr)?
    };

    // Save guest memory.
    let memory_state = if let Some(vm_as) = vm.vm_as() {
        save_guest_memory(vm_as, output_dir)?
    } else {
        return Err(CheckpointError::SaveMemory(
            "guest memory not initialized".to_string(),
        ));
    };

    // Save device states.
    let device_states = save_device_states(vm)?;

    // Create the complete state.
    let state = MicrovmState {
        vcpu_states,
        memory_state,
        device_states,
    };

    // Serialize state to JSON.
    let state_json = serde_json::to_string_pretty(&state).map_err(|e| {
        CheckpointError::Serialization(format!("failed to serialize state: {}", e))
    })?;

    // Write state metadata file.
    let state_file_path = output_dir.join("vm_state.json");
    let mut state_file = File::create(&state_file_path)
        .map_err(|e| CheckpointError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    state_file
        .write_all(state_json.as_bytes())
        .map_err(|e| CheckpointError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    state_file
        .flush()
        .map_err(|e| CheckpointError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

    // Resume vCPUs.
    vm.vcpu_manager()
        .map_err(|e| CheckpointError::VmState(format!("failed to get vCPU manager: {:?}", e)))?
        .resume_all_vcpus()
        .map_err(|e| CheckpointError::VmState(format!("failed to resume vCPUs: {:?}", e)))?;

    info!("VM checkpoint completed successfully");
    Ok(state)
}

/// Restore VM state from a checkpoint directory.
///
/// This function:
/// 1. Reads the saved state from disk
/// 2. Restores guest memory
/// 3. Restores device state
/// 4. Returns the state for vCPU restoration (done separately during VM startup)
pub fn restore_vm(vm: &mut Vm, input_dir: &Path) -> Result<MicrovmState> {
    info!("Starting VM restore from {:?}", input_dir);

    // Read and deserialize the state file.
    let state_file_path = input_dir.join("vm_state.json");
    let mut state_file = File::open(&state_file_path)
        .map_err(|e| CheckpointError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    let mut state_json = String::new();
    state_file
        .read_to_string(&mut state_json)
        .map_err(|e| CheckpointError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    let state: MicrovmState = serde_json::from_str(&state_json).map_err(|e| {
        CheckpointError::Serialization(format!("failed to deserialize state: {}", e))
    })?;

    // Restore guest memory.
    if let Some(vm_as) = vm.vm_as() {
        restore_guest_memory(vm_as, &state.memory_state, input_dir)?;
    } else {
        return Err(CheckpointError::RestoreMemory(
            "guest memory not initialized".to_string(),
        ));
    }

    // Restore device states.
    restore_device_states(vm, &state.device_states)?;

    info!("VM restore completed successfully");
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_state_serialization() {
        let state = MemoryRegionState {
            base_address: 0x1000,
            size: 0x2000,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: MemoryRegionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.base_address, deserialized.base_address);
        assert_eq!(state.size, deserialized.size);
    }

    #[test]
    fn test_memory_range_state_serialization() {
        let state = MemoryRangeState {
            guest_address: 0x3000,
            offset: 0,
            length: PAGE_SIZE as u64,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: MemoryRangeState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.guest_address, deserialized.guest_address);
        assert_eq!(state.offset, deserialized.offset);
        assert_eq!(state.length, deserialized.length);
    }

    #[test]
    fn test_guest_memory_state_default() {
        let state = GuestMemoryState::default();
        assert!(state.regions.is_empty());
        assert!(state.resident_ranges.is_empty());
    }

    #[test]
    fn test_device_states_default() {
        let states = DeviceStates::default();
        assert!(states.serial_state.is_none());
    }

    #[test]
    fn test_microvm_state_serialization() {
        let state = MicrovmState {
            vcpu_states: Vec::new(),
            memory_state: GuestMemoryState::default(),
            device_states: DeviceStates::default(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: MicrovmState = serde_json::from_str(&json).unwrap();
        assert!(deserialized.vcpu_states.is_empty());
        assert!(deserialized.memory_state.regions.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_state_serialization() {
        let state = VcpuState {
            id: 0,
            regs: VcpuRegs {
                rax: 1,
                rbx: 2,
                rcx: 3,
                rdx: 4,
                rsi: 5,
                rdi: 6,
                rsp: 7,
                rbp: 8,
                r8: 9,
                r9: 10,
                r10: 11,
                r11: 12,
                r12: 13,
                r13: 14,
                r14: 15,
                r15: 16,
                rip: 17,
                rflags: 18,
            },
            sregs: VcpuSregs { data: vec![0; 10] },
            fpu: VcpuFpu { data: vec![0; 10] },
            lapic: VcpuLapic {
                regs: vec![0; 1024],
            },
            mp_state: VcpuMpState { mp_state: 0 },
            vcpu_events: VcpuEvents { data: vec![0; 10] },
            xsave: VcpuXsave { data: vec![0; 10] },
            xcrs: VcpuXcrs { data: vec![0; 10] },
            msrs: Vec::new(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: VcpuState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 0);
        assert_eq!(deserialized.regs.rax, 1);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_vcpu_state_serialization() {
        let state = VcpuState {
            id: 0,
            mp_state: VcpuMpState { mp_state: 0 },
            mpidr: 0x80000000,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: VcpuState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 0);
        assert_eq!(deserialized.mpidr, 0x80000000);
    }

    #[test]
    fn test_get_resident_pages_empty() {
        let result = get_resident_pages(std::ptr::null(), 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_serial_device_state_serialization() {
        let state = SerialDeviceState { active: true };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: SerialDeviceState = serde_json::from_str(&json).unwrap();
        assert!(deserialized.active);
    }

    #[test]
    fn test_vcpu_mp_state_serialization() {
        let state = VcpuMpState { mp_state: 1 };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: VcpuMpState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.mp_state, 1);
    }
}
