// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for block devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring block device states during checkpoint/restore operations.
//! It captures the block device configuration, including disk paths,
//! rate limiter settings, and device identification.

use std::path::PathBuf;

use serde_derive::{Deserialize, Serialize};

/// Block device type for checkpoint state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockDeviceTypeState {
    /// Raw block device.
    RawBlock,
    /// Spool device.
    Spool,
    /// SPDK device.
    Spdk,
}

/// Saved state for rate limiter configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RateLimiterState {
    /// Bandwidth rate limit (bytes/s).
    pub bandwidth_size: u64,
    /// Bandwidth one-time burst.
    pub bandwidth_one_time_burst: u64,
    /// Bandwidth refill time in milliseconds.
    pub bandwidth_refill_time_ms: u64,
    /// Operations rate limit (ops/s).
    pub ops_size: u64,
    /// Operations one-time burst.
    pub ops_one_time_burst: u64,
    /// Operations refill time in milliseconds.
    pub ops_refill_time_ms: u64,
}

/// Saved state for a single block device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockDeviceState {
    /// Unique identifier for the device.
    pub drive_id: String,
    /// Block device type.
    pub device_type: BlockDeviceTypeState,
    /// Path to the disk image on the host.
    pub path_on_host: PathBuf,
    /// Whether this is the root device.
    pub is_root_device: bool,
    /// Partition UUID for the root device.
    pub part_uuid: Option<String>,
    /// Whether the device is read-only.
    pub is_read_only: bool,
    /// Whether to use O_DIRECT.
    pub is_direct: bool,
    /// Whether to keep the device file open.
    pub no_drop: bool,
    /// Number of virtio queues.
    pub num_queues: usize,
    /// Queue size.
    pub queue_size: u16,
    /// Rate limiter configuration.
    pub rate_limiter: Option<RateLimiterState>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: Option<bool>,
    /// Whether to use generic IRQ.
    pub use_generic_irq: Option<bool>,
    /// Whether to use PCI bus.
    pub use_pci_bus: Option<bool>,
    /// Assigned MMIO base address.
    pub mmio_base: Option<u64>,
    /// Assigned MMIO size.
    pub mmio_size: Option<u64>,
    /// Assigned IRQ number.
    pub irq: Option<u32>,
}

/// Saved state for the block device manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockDeviceMgrState {
    /// List of block device states.
    pub devices: Vec<BlockDeviceState>,
    /// Whether the VM has a root block device.
    pub has_root_block: bool,
    /// Whether a partition UUID is used for root device identification.
    pub has_part_uuid_root: bool,
    /// Whether root device is read-only.
    pub read_only_root: bool,
    /// Root partition UUID.
    pub part_uuid: Option<String>,
    /// Whether to use shared IRQ for block devices.
    pub use_shared_irq: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_device_state_serialize() {
        let state = BlockDeviceState {
            drive_id: "rootfs".to_string(),
            device_type: BlockDeviceTypeState::RawBlock,
            path_on_host: PathBuf::from("/dev/vda"),
            is_root_device: true,
            part_uuid: Some("uuid-1234".to_string()),
            is_read_only: false,
            is_direct: true,
            no_drop: false,
            num_queues: 1,
            queue_size: 256,
            rate_limiter: None,
            use_shared_irq: None,
            use_generic_irq: None,
            use_pci_bus: None,
            mmio_base: Some(0xd000_0000),
            mmio_size: Some(0x1000),
            irq: Some(5),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: BlockDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.drive_id, "rootfs");
        assert!(restored.is_root_device);
    }

    #[test]
    fn test_block_device_mgr_state_serialize() {
        let state = BlockDeviceMgrState {
            devices: vec![],
            has_root_block: false,
            has_part_uuid_root: false,
            read_only_root: false,
            part_uuid: None,
            use_shared_irq: true,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: BlockDeviceMgrState = serde_json::from_str(&json).unwrap();
        assert!(restored.use_shared_irq);
    }
}
