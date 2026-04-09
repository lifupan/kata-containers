// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for VM checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring the complete VM state during checkpoint/restore operations.
//! It captures VM configuration, memory layout, and instance information.

use serde_derive::{Deserialize, Serialize};

use crate::device_manager::device_manager_persistent::DeviceManagerState;
use crate::vcpu::vcpu_persistent::VcpuManagerState;
use crate::vm::{CpuTopology, NumaRegionInfo};

/// Saved state for VM configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmConfigState {
    /// Number of vCPUs to start.
    pub vcpu_count: u8,
    /// Maximum number of vCPUs.
    pub max_vcpu_count: u8,
    /// CPU power management.
    pub cpu_pm: String,
    /// CPU topology.
    pub cpu_topology: CpuTopology,
    /// VPMU feature level.
    pub vpmu_feature: u8,
    /// Memory type (hugetlbfs or shmem).
    pub mem_type: String,
    /// Memory file path.
    pub mem_file_path: String,
    /// Memory size in MiB.
    pub mem_size_mib: usize,
    /// Serial port socket path.
    pub serial_path: Option<String>,
    /// PCI hotplug enabled.
    pub pci_hotplug_enabled: bool,
}

/// Memory region descriptor for checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRegionState {
    /// Guest physical address base.
    pub guest_base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// KVM memory slot index.
    pub slot: u32,
    /// Offset into the memory file for this region.
    pub file_offset: u64,
}

/// Saved state for the address space manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddressSpaceState {
    /// Memory regions in guest physical address space.
    pub regions: Vec<MemoryRegionState>,
    /// NUMA region information.
    pub numa_regions: Vec<NumaRegionInfo>,
}

/// Complete saved state for a virtual machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmState {
    /// VM configuration.
    pub config: VmConfigState,
    /// Address space state.
    pub address_space: AddressSpaceState,
    /// Device manager state.
    pub device_manager: DeviceManagerState,
    /// vCPU manager state.
    pub vcpu_manager: VcpuManagerState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_config_state_serialize() {
        let state = VmConfigState {
            vcpu_count: 2,
            max_vcpu_count: 4,
            cpu_pm: "on".to_string(),
            cpu_topology: CpuTopology {
                threads_per_core: 1,
                cores_per_die: 2,
                dies_per_socket: 1,
                sockets: 1,
            },
            vpmu_feature: 0,
            mem_type: "shmem".to_string(),
            mem_file_path: "".to_string(),
            mem_size_mib: 256,
            serial_path: None,
            pci_hotplug_enabled: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: VmConfigState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.vcpu_count, 2);
        assert_eq!(restored.mem_size_mib, 256);
    }

    #[test]
    fn test_address_space_state_serialize() {
        let state = AddressSpaceState {
            regions: vec![MemoryRegionState {
                guest_base: 0x0,
                size: 256 << 20,
                slot: 0,
                file_offset: 0,
            }],
            numa_regions: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: AddressSpaceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.regions.len(), 1);
    }
}
