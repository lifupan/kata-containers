// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for the overall device manager checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring the complete device manager state, aggregating all individual
//! device manager states.

use serde_derive::{Deserialize, Serialize};

use super::console_manager_persistent::ConsoleManagerState;
use super::legacy_persistent::LegacyDeviceManagerState;

#[cfg(feature = "virtio-balloon")]
use super::balloon_dev_mgr_persistent::BalloonDeviceMgrState;
#[cfg(any(feature = "virtio-blk", feature = "vhost-user-blk"))]
use super::blk_dev_mgr_persistent::BlockDeviceMgrState;
#[cfg(feature = "virtio-mem")]
use super::mem_dev_mgr_persistent::MemDeviceMgrState;
#[cfg(feature = "virtio-net")]
use super::virtio_net_dev_mgr_persistent::VirtioNetDeviceMgrState;
#[cfg(feature = "virtio-vsock")]
use super::vsock_dev_mgr_persistent::VsockDeviceMgrState;

/// Saved state for the complete device manager.
///
/// This struct aggregates state from all device sub-managers to provide
/// a complete snapshot of all devices in the VM at checkpoint time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceManagerState {
    /// Legacy device manager state.
    pub legacy: Option<LegacyDeviceManagerState>,
    /// Console manager state.
    pub console: ConsoleManagerState,

    /// Block device manager state.
    #[cfg(any(feature = "virtio-blk", feature = "vhost-user-blk"))]
    pub block: BlockDeviceMgrState,

    /// Virtio-net device manager state.
    #[cfg(feature = "virtio-net")]
    pub virtio_net: VirtioNetDeviceMgrState,

    /// Vsock device manager state.
    #[cfg(feature = "virtio-vsock")]
    pub vsock: VsockDeviceMgrState,

    /// Balloon device manager state.
    #[cfg(feature = "virtio-balloon")]
    pub balloon: BalloonDeviceMgrState,

    /// Memory device manager state.
    #[cfg(feature = "virtio-mem")]
    pub mem: MemDeviceMgrState,
}

impl Default for DeviceManagerState {
    fn default() -> Self {
        DeviceManagerState {
            legacy: None,
            console: ConsoleManagerState::default(),
            #[cfg(any(feature = "virtio-blk", feature = "vhost-user-blk"))]
            block: BlockDeviceMgrState::default(),
            #[cfg(feature = "virtio-net")]
            virtio_net: VirtioNetDeviceMgrState::default(),
            #[cfg(feature = "virtio-vsock")]
            vsock: VsockDeviceMgrState::default(),
            #[cfg(feature = "virtio-balloon")]
            balloon: BalloonDeviceMgrState::default(),
            #[cfg(feature = "virtio-mem")]
            mem: MemDeviceMgrState::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_manager_state_default() {
        let state = DeviceManagerState::default();
        assert!(state.legacy.is_none());
    }

    #[test]
    fn test_device_manager_state_serialize() {
        let state = DeviceManagerState::default();
        let json = serde_json::to_string(&state).unwrap();
        let restored: DeviceManagerState = serde_json::from_str(&json).unwrap();
        assert!(restored.legacy.is_none());
    }
}
