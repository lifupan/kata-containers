// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for memory devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring virtio-mem device states during checkpoint/restore operations.
//! It captures the memory device configuration including size, capacity,
//! NUMA topology, and assigned resources.

use serde_derive::{Deserialize, Serialize};

/// Saved state for a single memory device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemDeviceState {
    /// Unique identifier for the memory device.
    pub mem_id: String,
    /// Current memory size in MiB.
    pub size_mib: u64,
    /// Maximum capacity in MiB.
    pub capacity_mib: u64,
    /// Whether to use multiple regions.
    pub multi_region: bool,
    /// Host NUMA node ID.
    pub host_numa_node_id: Option<u32>,
    /// Guest NUMA node ID.
    pub guest_numa_node_id: Option<u16>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: Option<bool>,
    /// Whether to use generic IRQ.
    pub use_generic_irq: Option<bool>,
    /// Assigned MMIO base address.
    pub mmio_base: Option<u64>,
    /// Assigned MMIO size.
    pub mmio_size: Option<u64>,
    /// Assigned IRQ number.
    pub irq: Option<u32>,
}

/// Saved state for the memory device manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemDeviceMgrState {
    /// List of memory device states.
    pub devices: Vec<MemDeviceState>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_device_state_serialize() {
        let state = MemDeviceState {
            mem_id: "mem0".to_string(),
            size_mib: 256,
            capacity_mib: 1024,
            multi_region: false,
            host_numa_node_id: Some(0),
            guest_numa_node_id: Some(1),
            use_shared_irq: None,
            use_generic_irq: None,
            mmio_base: Some(0xd000_4000),
            mmio_size: Some(0x1000),
            irq: Some(9),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: MemDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.mem_id, "mem0");
        assert_eq!(restored.size_mib, 256);
        assert_eq!(restored.capacity_mib, 1024);
    }

    #[test]
    fn test_mem_device_mgr_state_default() {
        let state = MemDeviceMgrState::default();
        assert!(state.devices.is_empty());
    }
}
