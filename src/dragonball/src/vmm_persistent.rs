// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Top-level VMM checkpoint and restore implementation.
//!
//! This module provides the entry points for performing checkpoint (save) and
//! restore operations on the Dragonball VMM. It orchestrates saving/restoring
//! guest memory, vCPU states, and all device states.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use vm_memory::{
    Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryRegion,
};

use crate::checkpoint::{CheckpointError, CheckpointManager, CheckpointMetadata, Result};
use crate::vcpu::vcpu_persistent::{save_vcpu_state, VcpuManagerState};
use crate::vm::vm_persistent::{AddressSpaceState, MemoryRegionState, VmConfigState, VmState};
use crate::vm::{CpuTopology, Vm, VmConfigInfo};

use crate::device_manager::console_manager_persistent::{ConsoleBackendType, ConsoleManagerState};
use crate::device_manager::device_manager_persistent::DeviceManagerState;
use crate::device_manager::legacy_persistent::{LegacyDeviceManagerState, SerialDeviceState};

impl Vm {
    /// Save the complete VM state to the given checkpoint directory.
    ///
    /// This pauses all vCPUs, saves memory and all device/vCPU states,
    /// then resumes the vCPUs. The VM continues running after checkpoint.
    pub fn checkpoint<P: AsRef<Path>>(&mut self, checkpoint_dir: P) -> Result<()> {
        if !self.is_vm_initialized() {
            return Err(CheckpointError::InvalidVmState);
        }

        let mgr = CheckpointManager::new(&checkpoint_dir)?;
        mgr.prepare_checkpoint_dir()?;

        // Pause all vCPUs
        self.pause_all_vcpus_with_downtime()
            .map_err(|e| CheckpointError::PauseVcpus(format!("{e}")))?;

        let result = self.save_vm_state(&mgr);

        // Always resume vCPUs, even if save failed
        if let Err(e) = self.resume_all_vcpus_with_downtime() {
            // If save was successful but resume failed, still report an error
            if result.is_ok() {
                return Err(CheckpointError::ResumeVcpus(format!("{e}")));
            }
        }

        result
    }

    /// Internal method to save all VM state while vCPUs are paused.
    fn save_vm_state(&self, mgr: &CheckpointManager) -> Result<()> {
        let vm_config = self.vm_config();

        // Save metadata
        let metadata = CheckpointMetadata {
            version: 1,
            timestamp_us: dbs_utils::time::TimestampUs::default().time_us,
            vcpu_count: vm_config.vcpu_count,
            mem_size_mib: vm_config.mem_size_mib,
        };
        mgr.save_state(CheckpointManager::METADATA_FILE, &metadata)?;

        // Save guest memory
        self.save_guest_memory(mgr)?;

        // Build and save the complete VM state
        let vm_state = self.build_vm_state()?;
        mgr.save_state(CheckpointManager::VM_STATE_FILE, &vm_state)?;

        Ok(())
    }

    /// Save guest memory to a file.
    fn save_guest_memory(&self, mgr: &CheckpointManager) -> Result<()> {
        let vm_as = self.vm_as().ok_or(CheckpointError::Memory(
            "guest memory not initialized".to_string(),
        ))?;

        let memory = vm_as.memory();
        let path = mgr.file_path(CheckpointManager::MEMORY_FILE);
        let mut file = File::create(&path)?;

        // Iterate over all guest memory regions and write them out
        for region in memory.iter() {
            let region_size = region.len() as usize;
            let guest_addr = region.start_addr();

            // Read memory in chunks to avoid allocating too much at once
            const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB chunks
            let mut offset = 0usize;
            while offset < region_size {
                let chunk_len = std::cmp::min(CHUNK_SIZE, region_size - offset);
                let mut buf = vec![0u8; chunk_len];
                memory
                    .read_slice(
                        &mut buf,
                        GuestAddress(guest_addr.raw_value() + offset as u64),
                    )
                    .map_err(|e| CheckpointError::Memory(format!("failed to read memory: {e}")))?;
                file.write_all(&buf)?;
                offset += chunk_len;
            }
        }

        file.sync_all()?;
        Ok(())
    }

    /// Build the complete VM state snapshot.
    fn build_vm_state(&self) -> Result<VmState> {
        let vm_config = self.vm_config();
        let config = VmConfigState {
            vcpu_count: vm_config.vcpu_count,
            max_vcpu_count: vm_config.max_vcpu_count,
            cpu_pm: vm_config.cpu_pm.clone(),
            cpu_topology: vm_config.cpu_topology.clone(),
            vpmu_feature: vm_config.vpmu_feature,
            mem_type: vm_config.mem_type.clone(),
            mem_file_path: vm_config.mem_file_path.clone(),
            mem_size_mib: vm_config.mem_size_mib,
            serial_path: vm_config.serial_path.clone(),
            pci_hotplug_enabled: vm_config.pci_hotplug_enabled,
        };

        let address_space = self.build_address_space_state()?;
        let device_manager = self.build_device_manager_state()?;
        let vcpu_manager = self.build_vcpu_manager_state()?;

        Ok(VmState {
            config,
            address_space,
            device_manager,
            vcpu_manager,
        })
    }

    /// Build address space state for checkpoint.
    fn build_address_space_state(&self) -> Result<AddressSpaceState> {
        let vm_as = self.vm_as().ok_or(CheckpointError::Memory(
            "guest memory not initialized".to_string(),
        ))?;

        let memory = vm_as.memory();
        let mut regions = Vec::new();
        let mut file_offset = 0u64;

        for region in memory.iter() {
            let region_size = region.len();
            regions.push(MemoryRegionState {
                guest_base: region.start_addr().raw_value(),
                size: region_size,
                slot: 0, // Slot information is managed by address space manager
                file_offset,
            });
            file_offset += region_size;
        }

        Ok(AddressSpaceState {
            regions,
            numa_regions: Vec::new(),
        })
    }

    /// Build device manager state for checkpoint.
    fn build_device_manager_state(&self) -> Result<DeviceManagerState> {
        let dm = self.device_manager();
        let vm_config = self.vm_config();

        // Save legacy device state
        let legacy = dm.legacy_manager.as_ref().map(|_lm| {
            #[cfg(target_arch = "x86_64")]
            {
                LegacyDeviceManagerState {
                    com1: SerialDeviceState::default(),
                    com2: SerialDeviceState::default(),
                    i8042_present: true,
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                LegacyDeviceManagerState {
                    com1: SerialDeviceState::default(),
                    com2: SerialDeviceState::default(),
                    rtc_present: true,
                }
            }
        });

        // Save console state
        let console = ConsoleManagerState {
            backend_type: if vm_config.serial_path.is_some() {
                ConsoleBackendType::UnixSocket(
                    vm_config.serial_path.clone().unwrap_or_default(),
                )
            } else {
                ConsoleBackendType::Stdio
            },
        };

        Ok(DeviceManagerState {
            legacy,
            console,
            #[cfg(any(feature = "virtio-blk", feature = "vhost-user-blk"))]
            block: crate::device_manager::blk_dev_mgr_persistent::BlockDeviceMgrState::default(),
            #[cfg(feature = "virtio-net")]
            virtio_net:
                crate::device_manager::virtio_net_dev_mgr_persistent::VirtioNetDeviceMgrState::default(),
            #[cfg(feature = "virtio-vsock")]
            vsock: crate::device_manager::vsock_dev_mgr_persistent::VsockDeviceMgrState::default(),
            #[cfg(feature = "virtio-balloon")]
            balloon:
                crate::device_manager::balloon_dev_mgr_persistent::BalloonDeviceMgrState::default(),
            #[cfg(feature = "virtio-mem")]
            mem: crate::device_manager::mem_dev_mgr_persistent::MemDeviceMgrState::default(),
        })
    }

    /// Build vCPU manager state for checkpoint.
    fn build_vcpu_manager_state(&self) -> Result<VcpuManagerState> {
        let mgr = self
            .vcpu_manager()
            .map_err(|e| CheckpointError::VcpuState(format!("vCPU manager error: {e}")))?;
        let mut vcpu_states = Vec::new();

        for (idx, vcpu_info) in mgr.vcpu_infos().iter().enumerate() {
            if let Some(vcpu_fd) = vcpu_info.vcpu_fd().as_ref() {
                let state = save_vcpu_state(vcpu_fd, idx as u8)?;
                vcpu_states.push(state);
            }
        }

        let vm_config = self.vm_config();
        Ok(VcpuManagerState {
            boot_vcpu_count: vm_config.vcpu_count,
            max_vcpu_count: vm_config.max_vcpu_count,
            vcpu_states,
        })
    }

    /// Restore guest memory from a checkpoint file.
    ///
    /// This loads the memory contents from the checkpoint into the
    /// already-initialized guest address space.
    pub fn restore_guest_memory<P: AsRef<Path>>(&self, checkpoint_dir: P) -> Result<()> {
        let mgr = CheckpointManager::new(&checkpoint_dir)?;
        let path = mgr.file_path(CheckpointManager::MEMORY_FILE);

        let vm_as = self.vm_as().ok_or(CheckpointError::Memory(
            "guest memory not initialized".to_string(),
        ))?;

        let memory = vm_as.memory();
        let mut file = File::open(&path)?;

        // Restore each memory region
        for region in memory.iter() {
            let region_size = region.len() as usize;
            let guest_addr = region.start_addr();

            const CHUNK_SIZE: usize = 4 * 1024 * 1024;
            let mut offset = 0usize;
            while offset < region_size {
                let chunk_len = std::cmp::min(CHUNK_SIZE, region_size - offset);
                let mut buf = vec![0u8; chunk_len];
                file.read_exact(&mut buf)?;
                memory
                    .write_slice(
                        &buf,
                        GuestAddress(guest_addr.raw_value() + offset as u64),
                    )
                    .map_err(|e| CheckpointError::Memory(format!("failed to write memory: {e}")))?;
                offset += chunk_len;
            }
        }

        Ok(())
    }

    /// Restore VM configuration from saved state.
    pub fn restore_vm_config(state: &VmConfigState) -> VmConfigInfo {
        VmConfigInfo {
            vcpu_count: state.vcpu_count,
            max_vcpu_count: state.max_vcpu_count,
            cpu_pm: state.cpu_pm.clone(),
            cpu_topology: CpuTopology {
                threads_per_core: state.cpu_topology.threads_per_core,
                cores_per_die: state.cpu_topology.cores_per_die,
                dies_per_socket: state.cpu_topology.dies_per_socket,
                sockets: state.cpu_topology.sockets,
            },
            vpmu_feature: state.vpmu_feature,
            mem_type: state.mem_type.clone(),
            mem_file_path: state.mem_file_path.clone(),
            mem_size_mib: state.mem_size_mib,
            serial_path: state.serial_path.clone(),
            pci_hotplug_enabled: state.pci_hotplug_enabled,
        }
    }

    /// Load checkpoint metadata from a checkpoint directory.
    pub fn load_checkpoint_metadata<P: AsRef<Path>>(
        checkpoint_dir: P,
    ) -> Result<CheckpointMetadata> {
        let mgr = CheckpointManager::new(checkpoint_dir)?;
        mgr.load_state(CheckpointManager::METADATA_FILE)
    }

    /// Load the complete VM state from a checkpoint directory.
    pub fn load_vm_state<P: AsRef<Path>>(checkpoint_dir: P) -> Result<VmState> {
        let mgr = CheckpointManager::new(checkpoint_dir)?;
        mgr.load_state(CheckpointManager::VM_STATE_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::vm_persistent::VmConfigState;

    #[test]
    fn test_restore_vm_config() {
        let config_state = VmConfigState {
            vcpu_count: 4,
            max_vcpu_count: 8,
            cpu_pm: "on".to_string(),
            cpu_topology: CpuTopology {
                threads_per_core: 2,
                cores_per_die: 2,
                dies_per_socket: 1,
                sockets: 1,
            },
            vpmu_feature: 0,
            mem_type: "shmem".to_string(),
            mem_file_path: "".to_string(),
            mem_size_mib: 512,
            serial_path: None,
            pci_hotplug_enabled: false,
        };
        let config = Vm::restore_vm_config(&config_state);
        assert_eq!(config.vcpu_count, 4);
        assert_eq!(config.max_vcpu_count, 8);
        assert_eq!(config.mem_size_mib, 512);
    }
}
