// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for virtio-net devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring virtio network device states during checkpoint/restore operations.
//! It captures the network device configuration, including MAC address,
//! queue settings, rate limiter configuration, and assigned resources.

use serde_derive::{Deserialize, Serialize};

use super::blk_dev_mgr_persistent::RateLimiterState;

/// Saved state for a single virtio-net device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtioNetDeviceState {
    /// Unique identifier for the interface.
    pub iface_id: String,
    /// Name of the TAP device on the host.
    pub host_dev_name: String,
    /// Number of virtio queues.
    pub num_queues: usize,
    /// Queue size.
    pub queue_size: u16,
    /// Guest MAC address (if configured).
    pub guest_mac: Option<String>,
    /// RX rate limiter configuration.
    pub rx_rate_limiter: Option<RateLimiterState>,
    /// TX rate limiter configuration.
    pub tx_rate_limiter: Option<RateLimiterState>,
    /// Whether duplicate MAC addresses are allowed.
    pub allow_duplicate_mac: bool,
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

/// Saved state for the virtio-net device manager.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VirtioNetDeviceMgrState {
    /// List of virtio-net device states.
    pub devices: Vec<VirtioNetDeviceState>,
    /// Whether to use shared IRQ.
    pub use_shared_irq: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_net_device_state_serialize() {
        let state = VirtioNetDeviceState {
            iface_id: "eth0".to_string(),
            host_dev_name: "tap0".to_string(),
            num_queues: 2,
            queue_size: 256,
            guest_mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_duplicate_mac: false,
            use_shared_irq: None,
            use_generic_irq: None,
            mmio_base: Some(0xd000_1000),
            mmio_size: Some(0x1000),
            irq: Some(6),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: VirtioNetDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.iface_id, "eth0");
        assert_eq!(restored.host_dev_name, "tap0");
    }

    #[test]
    fn test_virtio_net_device_mgr_state_default() {
        let state = VirtioNetDeviceMgrState::default();
        assert!(state.devices.is_empty());
        assert!(!state.use_shared_irq);
    }
}
