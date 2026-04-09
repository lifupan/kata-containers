// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for vsock devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring vsock device states during checkpoint/restore operations.
//! It captures the vsock device configuration, including CID, paths,
//! queue settings, and assigned resources.

use serde_derive::{Deserialize, Serialize};

/// Saved state for a single vsock device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VsockDeviceState {
    /// Unique identifier for the device.
    pub id: String,
    /// Guest CID (Context Identifier).
    pub guest_cid: u32,
    /// Unix domain socket path for the backend.
    pub uds_path: Option<String>,
    /// TCP address for the backend.
    pub tcp_addr: Option<String>,
    /// Queue sizes.
    pub queue_size: Vec<u16>,
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

/// Saved state for the vsock device manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VsockDeviceMgrState {
    /// List of vsock device states.
    pub devices: Vec<VsockDeviceState>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_device_state_serialize() {
        let state = VsockDeviceState {
            id: "vsock0".to_string(),
            guest_cid: 3,
            uds_path: Some("/tmp/vsock.sock".to_string()),
            tcp_addr: None,
            queue_size: vec![256, 256],
            use_shared_irq: None,
            use_generic_irq: None,
            mmio_base: Some(0xd000_2000),
            mmio_size: Some(0x1000),
            irq: Some(7),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: VsockDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "vsock0");
        assert_eq!(restored.guest_cid, 3);
    }

    #[test]
    fn test_vsock_device_mgr_state_default() {
        let state = VsockDeviceMgrState::default();
        assert!(state.devices.is_empty());
    }
}
