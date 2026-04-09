// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for balloon devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring virtio-balloon device states during checkpoint/restore operations.
//! It captures the balloon device configuration including size, deflation
//! policy, and assigned resources.

use serde_derive::{Deserialize, Serialize};

/// Saved state for a single balloon device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalloonDeviceState {
    /// Unique identifier for the balloon device.
    pub balloon_id: String,
    /// Current balloon size in MiB.
    pub size_mib: u64,
    /// Whether to use shared IRQ.
    pub use_shared_irq: Option<bool>,
    /// Whether to use generic IRQ.
    pub use_generic_irq: Option<bool>,
    /// Whether deflate on OOM is enabled.
    pub f_deflate_on_oom: bool,
    /// Whether free page reporting is enabled.
    pub f_reporting: bool,
    /// Assigned MMIO base address.
    pub mmio_base: Option<u64>,
    /// Assigned MMIO size.
    pub mmio_size: Option<u64>,
    /// Assigned IRQ number.
    pub irq: Option<u32>,
}

/// Saved state for the balloon device manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BalloonDeviceMgrState {
    /// List of balloon device states.
    pub devices: Vec<BalloonDeviceState>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balloon_device_state_serialize() {
        let state = BalloonDeviceState {
            balloon_id: "balloon0".to_string(),
            size_mib: 128,
            use_shared_irq: None,
            use_generic_irq: None,
            f_deflate_on_oom: true,
            f_reporting: false,
            mmio_base: Some(0xd000_3000),
            mmio_size: Some(0x1000),
            irq: Some(8),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: BalloonDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.balloon_id, "balloon0");
        assert_eq!(restored.size_mib, 128);
        assert!(restored.f_deflate_on_oom);
    }

    #[test]
    fn test_balloon_device_mgr_state_default() {
        let state = BalloonDeviceMgrState::default();
        assert!(state.devices.is_empty());
    }
}
