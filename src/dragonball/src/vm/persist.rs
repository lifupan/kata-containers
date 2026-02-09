// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright (C) 2025 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures and methods for saving and restoring the VM state
//! used in the checkpoint/snapshot feature.

use serde::{Deserialize, Serialize};

use crate::memory_snapshot::GuestMemoryState;
use crate::memory_snapshot::SnapshotMemory;
use crate::vm::Vm;

/// Serializable VM configuration state for snapshot persistence.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VmConfigState {
    /// Number of vcpus.
    pub vcpu_count: u8,
    /// Max number of vcpus.
    pub max_vcpu_count: u8,
    /// CPU power management setting.
    pub cpu_pm: String,
    /// Memory type (e.g., "shmem" or "hugetlbfs").
    pub mem_type: String,
    /// Memory file path.
    pub mem_file_path: String,
    /// Memory size in MiB.
    pub mem_size_mib: usize,
    /// Serial path.
    pub serial_path: Option<String>,
}

/// The complete VM state used for snapshot persistence.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VmState {
    /// VM configuration state.
    pub config: VmConfigState,
    /// Guest memory layout state.
    pub memory_state: GuestMemoryState,
}

/// Errors associated with saving the VM state.
#[derive(Debug, thiserror::Error)]
pub enum SaveVmStateError {
    /// Failed to save VM configuration.
    #[error("Failed to save VM configuration")]
    SaveVmConfig,
    /// Guest memory is not initialized.
    #[error("Guest memory is not initialized")]
    GuestMemoryNotInitialized,
}

/// Errors associated with restoring the VM state.
#[derive(Debug, thiserror::Error)]
pub enum RestoreVmStateError {
    /// Failed to restore VM configuration.
    #[error("Failed to restore VM configuration")]
    RestoreVmConfig,
}

impl Vm {
    /// Save the current VM state for snapshot.
    pub fn save_state(&self) -> Result<VmState, SaveVmStateError> {
        let config = VmConfigState {
            vcpu_count: self.vm_config.vcpu_count,
            max_vcpu_count: self.vm_config.max_vcpu_count,
            cpu_pm: self.vm_config.cpu_pm.clone(),
            mem_type: self.vm_config.mem_type.clone(),
            mem_file_path: self.vm_config.mem_file_path.clone(),
            mem_size_mib: self.vm_config.mem_size_mib,
            serial_path: self.vm_config.serial_path.clone(),
        };

        let memory_state = match self.vm_as() {
            Some(vm_as) => {
                use vm_memory::GuestAddressSpace;
                vm_as
                    .memory()
                    .describe(self.vm_address_space())
            }
            None => GuestMemoryState::default(),
        };

        Ok(VmState {
            config,
            memory_state,
        })
    }

    /// Save the current VM state for live upgrade.
    pub fn live_upgrade_save_state(&mut self) -> Result<VmState, SaveVmStateError> {
        self.save_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::tests::create_vm_instance;

    #[test]
    fn test_save_state_basic() {
        let mut vm = create_vm_instance();
        let vm_config = crate::vm::VmConfigInfo {
            vcpu_count: 1,
            max_vcpu_count: 1,
            cpu_pm: "off".to_string(),
            mem_type: "shmem".to_string(),
            mem_file_path: "".to_string(),
            mem_size_mib: 1,
            serial_path: None,
            cpu_topology: crate::vm::CpuTopology::default(),
            vpmu_feature: 0,
            pci_hotplug_enabled: false,
        };
        vm.set_vm_config(vm_config);
        vm.init_guest_memory().unwrap();

        let state = vm.save_state().unwrap();
        assert_eq!(state.config.vcpu_count, 1);
        assert_eq!(state.config.mem_size_mib, 1);
        assert_eq!(state.config.cpu_pm, "off");
    }

    #[test]
    fn test_save_state_serialization_roundtrip() {
        let mut vm = create_vm_instance();
        let vm_config = crate::vm::VmConfigInfo {
            vcpu_count: 2,
            max_vcpu_count: 4,
            cpu_pm: "off".to_string(),
            mem_type: "shmem".to_string(),
            mem_file_path: "".to_string(),
            mem_size_mib: 16,
            serial_path: None,
            cpu_topology: crate::vm::CpuTopology::default(),
            vpmu_feature: 0,
            pci_hotplug_enabled: false,
        };
        vm.set_vm_config(vm_config);
        vm.init_guest_memory().unwrap();

        let state = vm.save_state().unwrap();

        // Test snapshot serialization roundtrip using dbs_snapshot
        let mut buf = Vec::new();
        dbs_snapshot::Snapshot::new(&state)
            .save(&mut buf)
            .unwrap();

        let restored: dbs_snapshot::Snapshot<VmState> =
            dbs_snapshot::Snapshot::load(&mut buf.as_slice()).unwrap();
        assert_eq!(state, restored.data);
    }
}
